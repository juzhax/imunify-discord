#!/usr/bin/python3 -I
"""ImunifyAV Discord hook: bounded payload parsing and successful-delivery deduplication."""
import argparse
import hashlib
import json
import os
import re
import socket
import sqlite3
import stat
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

WEBHOOK = Path('/etc/imunify-discord/webhook')
STATE = Path('/var/lib/imunify-discord')
EVENTS = ('CUSTOM_SCAN_MALWARE_FOUND', 'USER_SCAN_MALWARE_FOUND')
MAX_INPUT = 1024 * 1024
DEDUP_SECONDS = 300


def validate_webhook(value):
    if not re.fullmatch(r'https://(?:discord\.com|discordapp\.com)/api/webhooks/[0-9]+/[A-Za-z0-9_-]+', value):
        raise ValueError('Invalid Discord webhook URL; expected HTTPS Discord webhook without query parameters.')
    return value


def scalar(value):
    return str(value) if isinstance(value, (str, int, float)) and not isinstance(value, bool) else ''


def first(data, *names):
    return next((scalar(data.get(name)) for name in names if scalar(data.get(name))), '')


def clean(value, limit=220):
    value = re.sub(r'https://(?:discord\.com|discordapp\.com)/api/webhooks/[^\s]+', '[redacted webhook]', scalar(value))
    value = ''.join(c if c.isprintable() else ' ' for c in value)
    return value.replace('`', "'").replace('@', '@\u200b')[:limit]


def path_user(path):
    match = re.match(r'^/home/([^/]+)/', path + '/')
    return match.group(1) if match else ''


def normalize(raw):
    """Accept the documented flat schema and common data/params wrappers."""
    data = raw if isinstance(raw, dict) else {}
    layers = [data]
    for _ in range(4):
        nested = next((data[k] for k in ('data', 'params', 'payload') if isinstance(data.get(k), dict)), None)
        if nested is None:
            break
        data = nested
        layers.append(data)
    merged = {}
    for layer in layers:
        merged.update(layer)
    candidates = [first(merged, key) for key in ('event_id', 'event', 'event_type')]
    if isinstance(merged.get('event'), dict):
        candidates.append(first(merged['event'], 'event_id', 'name', 'type'))
    if first(merged, 'type') in EVENTS:
        candidates.append(first(merged, 'type'))
    event_type = next((c for c in candidates if c in EVENTS), next((c for c in candidates if c), ''))
    user = first(merged, 'username', 'user', 'owner')
    if not user and isinstance(merged.get('user'), dict):
        user = first(merged['user'], 'username', 'name', 'login')
    path = first(merged, 'path', 'scan_path')
    records = []

    def add(item, owner=''):
        item = {'path': item} if isinstance(item, str) else item
        if not isinstance(item, dict):
            return
        record = {'path': first(item, 'path', 'file', 'filename', 'file_path'),
                  'user': first(item, 'username', 'user', 'owner') or owner,
                  'signature': first(item, 'signature', 'malware_name', 'threat'),
                  'hash': first(item, 'sha256', 'hash', 'checksum'),
                  'id': first(item, 'detection_id', 'id')}
        kind = first(item, 'type')
        if not record['signature'] and kind not in EVENTS + ('user', 'background', 'on-demand', 'custom'):
            record['signature'] = kind
        record['user'] = record['user'] or path_user(record['path']) or user
        if any(record[k] for k in ('path', 'signature', 'hash', 'id')):
            records.append(record)

    files = next((merged[k] for k in ('malicious_files', 'detections', 'infected_files', 'files')
                  if isinstance(merged.get(k), (list, dict))), [])
    if isinstance(files, list):
        for item in files:
            add(item)
    elif any(k in files for k in ('path', 'file', 'filename', 'file_path')):
        add(files)
    else:
        for owner, items in files.items():
            if isinstance(owner, str) and owner.startswith('/'):
                add(dict(items, path=owner) if isinstance(items, dict) else {'path': owner, 'signature': scalar(items)})
                continue
            for item in (items if isinstance(items, list) else [items]):
                add(item, scalar(owner))
    # Some versions send a single detection instead of a malicious_files list.
    if not records and any(k in merged for k in ('signature', 'malware_name', 'threat', 'file_path')):
        add(merged)
    return {'event_type': event_type or 'UNKNOWN_MALWARE_EVENT', 'user': user or path_user(path),
            'path': path, 'scan_id': first(merged, 'scan_id'),
            'occurrence': first(merged, 'started', 'completed'), 'records': records,
            'total': first(merged, 'total_malicious', 'malicious_total', 'malware_count')}


def parse_event(raw):
    try:
        return normalize(json.loads(raw))
    except (ValueError, TypeError, RecursionError):
        # Missing/malformed metadata must not discard a registered malware event.
        return normalize({})


def payload(event=None, test=False, simulated=False):
    if test:
        content = 'ImunifyAV Discord test: notification delivery is working. No scan was started.'
    else:
        event = event or normalize({})
        users = sorted({r['user'] for r in event['records'] if r['user']} | ({event['user']} if event['user'] else set()))
        lines = ['SIMULATED TEST — no scan or detection history changed.' if simulated else '**ImunifyAV malware detected**',
                 'Server: ' + clean(socket.gethostname(), 100),
                 'Event: ' + clean(event['event_type'], 80),
                 'Affected user(s): ' + (clean(', '.join(users), 220) or 'not supplied'),
                 'Scan path: ' + (clean(event['path']) or 'not supplied'),
                 'Detected malware: ' + (clean(event['total'], 30) or (str(len(event['records'])) if event['records'] else 'not supplied'))]
        if not event['records']:
            lines.append('File/signature details were not supplied by ImunifyAV.')
        for record in event['records'][:6]:
            details = clean(record['path']) or 'path not supplied'
            if record['signature']:
                details += ' | signature: ' + clean(record['signature'], 120)
            if record['hash']:
                details += ' | hash: ' + clean(record['hash'], 80)
            lines.append('- ' + details)
        footer = '\nReview findings in DirectAdmin → ImunifyAV. No cleanup, quarantine or deletion was requested.'
        content = '\n'.join(lines)[:1800] + footer
    return {'username': clean(socket.gethostname(), 80), 'content': content,
            'allowed_mentions': {'parse': []}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send(data, webhook):
    request = urllib.request.Request(validate_webhook(webhook), data=json.dumps(data).encode('utf-8'),
                                    headers={'Content-Type': 'application/json', 'User-Agent': 'imunify-discord/0.2'}, method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=20) as response:
        if response.status not in (200, 204):
            raise ValueError('Discord returned an unexpected status.')


def fingerprints(event):
    scope = event['scan_id'] or event['occurrence']
    identities = []
    for record in event['records']:
        if record['path'] or record['id'] or record['hash']:
            identities.append([scope, record['path'], record['user'], record['signature'], record['hash'], record['id']])
    if not identities and not event['records'] and scope:
        identities = [[scope, event['user'], event['path']]]
    return [hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest() for item in identities]


def open_cache(state):
    info = state.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise OSError('Untrusted cache directory')
    path = state / 'deliveries.sqlite3'
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise OSError('Untrusted cache file')
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    return sqlite3.connect(path, timeout=25)


def deliver(event, webhook, state=None, sender=None, now=None):
    """Serialize send+record; failed delivery never enters the cache."""
    sender = sender or send
    keys = fingerprints(event)
    if not keys:
        sender(payload(event), webhook)
        return True
    connection = None
    delivered = False
    attempted = False
    try:
        connection = open_cache(state or STATE)
        connection.execute('BEGIN IMMEDIATE')
        connection.execute('CREATE TABLE IF NOT EXISTS seen (fingerprint TEXT PRIMARY KEY, sent REAL NOT NULL)')
        timestamp = time.time() if now is None else now
        connection.execute('DELETE FROM seen WHERE sent <= ? OR sent > ?', (timestamp - DEDUP_SECONDS, timestamp + 60))
        seen = {row[0] for row in connection.execute('SELECT fingerprint FROM seen')}
        if all(key in seen for key in keys):
            connection.commit()
            return False
        # Send the whole scan summary if it includes any unseen finding. This
        # prevents one new finding being hidden by an overlapping prior batch.
        attempted = True
        sender(payload(event), webhook)
        delivered = True
        connection.executemany('INSERT OR REPLACE INTO seen VALUES (?, ?)', [(key, timestamp) for key in keys])
        connection.execute('DELETE FROM seen WHERE rowid NOT IN (SELECT rowid FROM seen ORDER BY sent DESC LIMIT 20000)')
        connection.commit()
        return True
    except (sqlite3.Error, OSError):
        if attempted and not delivered:
            raise
        # Prefer an extra alert over silently losing malware findings.
        print('Warning: duplicate cache unavailable; alert delivery will continue without suppression.', file=sys.stderr)
        if not delivered:
            sender(payload(event), webhook)
        return True
    finally:
        if connection is not None:
            connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--test', action='store_true', help='send a harmless delivery test')
    mode.add_argument('--test-event', choices=EVENTS + ('both',), help='simulate an event without scanning or changing ImunifyAV history')
    args = parser.parse_args()
    try:
        webhook = WEBHOOK.read_text().strip()
        if args.test:
            send(payload(test=True), webhook)
        elif args.test_event:
            for event_type in EVENTS if args.test_event == 'both' else (args.test_event,):
                event = normalize({'event_id': event_type, 'username': 'example-user',
                                   'path': '/home/example-user', 'malicious_files': [
                                       {'path': '/home/example-user/public_html/example.php',
                                        'signature': 'SIMULATED-DETECTION-NOT-MALWARE'}]})
                # Simulations deliberately bypass and do not alter live dedup state.
                send(payload(event, simulated=True), webhook)
        else:
            raw = sys.stdin.buffer.read(MAX_INPUT + 1)
            event = parse_event(raw if len(raw) <= MAX_INPUT else b'')
            if event['event_type'] not in EVENTS + ('UNKNOWN_MALWARE_EVENT',):
                return 0
            deliver(event, webhook)
    except urllib.error.HTTPError as exc:
        print('Error: Discord returned HTTP %s; check webhook validity or rate limits.' % exc.code, file=sys.stderr)
        return 1
    except Exception:
        print('Error: notification failed; check webhook permissions, DNS, HTTPS access and URL format.', file=sys.stderr)
        return 1
    if args.test or args.test_event:
        print('Discord test sent.' if args.test else 'Simulated Discord event notification(s) sent.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
