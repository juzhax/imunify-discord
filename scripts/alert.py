#!/usr/bin/python3
"""ImunifyAV notification hook. No third-party packages or secret arguments."""
import argparse
import json
import re
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path

WEBHOOK = Path('/etc/imunify-discord/webhook')
MAX_INPUT = 1024 * 1024


def validate_webhook(value):
    if not re.fullmatch(r'https://(?:discord\.com|discordapp\.com)/api/webhooks/[0-9]+/[A-Za-z0-9_-]+', value):
        raise ValueError('Invalid Discord webhook URL; expected HTTPS Discord webhook without query parameters.')
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def payload(event=None, test=False):
    # Never relay arbitrary event JSON, file contents, or incoming command arguments.
    content = ('ImunifyAV Discord test: notification delivery is working. No scan was started.'
               if test else 'ImunifyAV detected malware during an on-demand scan. '
               'Review the ImunifyAV malware list on this server. No remediation was requested by imunify-discord.')
    return {'username': socket.gethostname()[:80], 'content': content,
            'allowed_mentions': {'parse': []}}


def send(data, webhook):
    request = urllib.request.Request(validate_webhook(webhook),
                                    data=json.dumps(data).encode('utf-8'),
                                    headers={'Content-Type': 'application/json',
                                             'User-Agent': 'imunify-discord/1.0'}, method='POST')
    # Ignore proxy environment variables; do not forward this secret to a proxy or redirect.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=20) as response:
        if response.status not in (200, 204):
            raise ValueError('Discord returned an unexpected status.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test', action='store_true', help='send a harmless test notification')
    args = parser.parse_args()
    try:
        # The hook is registered only on CUSTOM_SCAN_MALWARE_FOUND. Consume stdin
        # without relying on version-specific event schema; never log its contents.
        if not args.test:
            sys.stdin.buffer.read(MAX_INPUT)
        send(payload(test=args.test), WEBHOOK.read_text().strip())
    except urllib.error.HTTPError as exc:
        print('Error: Discord returned HTTP %s; check webhook validity or rate limits.' % exc.code, file=sys.stderr)
        return 1
    except Exception:
        # urllib exceptions can contain the secret URL. Never print exception text.
        print('Error: notification failed; check webhook permissions, DNS, HTTPS access and URL format.', file=sys.stderr)
        return 1
    if args.test:
        print('Discord test sent.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
