"""Both official ImunifyAV event types, tolerant parsing and persistent dedup."""
from concurrent.futures import ThreadPoolExecutor
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import alert
import manage


def example(event_type=alert.EVENTS[0], path='/home/example-user/public_html/infected.php', scan_id='example-scan'):
    return {'event_id': event_type, 'scan_id': scan_id, 'path': '/home/example-user',
            'malicious_files': [path], 'total_malicious': 1}


class AlertParsingTests(unittest.TestCase):
    def test_official_flat_schema_both_events(self):
        for event_type in alert.EVENTS:
            with self.subTest(event=event_type):
                event = alert.parse_event(json.dumps(example(event_type)))
                self.assertEqual(event['event_type'], event_type)
                self.assertEqual(event['user'], 'example-user')
                with patch.object(alert.socket, 'gethostname', return_value='host.example.invalid'):
                    message = alert.payload(event)
                for value in (event_type, 'example-user', 'infected.php', 'host.example.invalid', 'DirectAdmin → ImunifyAV'):
                    self.assertIn(value, message['content'])
                self.assertEqual(message['allowed_mentions'], {'parse': []})

    def test_wrapped_records_and_signatures(self):
        event = alert.normalize({'event': {'name': alert.EVENTS[1]}, 'data': {'params': {
            'user': {'username': 'example-user'}, 'scan_path': '/srv/sites',
            'detections': [{'filename': '/srv/sites/bad.php', 'malware_name': 'EXAMPLE-SIGNATURE', 'sha256': 'a' * 64}]}}})
        self.assertEqual(event['event_type'], alert.EVENTS[1])
        self.assertEqual(event['user'], 'example-user')
        self.assertIn('EXAMPLE-SIGNATURE', alert.payload(event)['content'])
        self.assertIn('a' * 64, alert.payload(event)['content'])
        event = alert.normalize({'event_id': 'example-identifier', 'type': alert.EVENTS[1]})
        self.assertEqual(event['event_type'], alert.EVENTS[1])

    def test_missing_null_and_malformed_fields_do_not_crash(self):
        for raw in ('', '{broken', '[]', 'null', 'false', '123', '{}',
                    '{"event_id":null,"malicious_files":null}',
                    '{"data":{"path":[],"user":false,"malicious_files":[null,42,{},[]]}}'):
            with self.subTest(raw=raw):
                event = alert.parse_event(raw)
                self.assertIn('DirectAdmin', alert.payload(event)['content'])
        message = alert.payload(alert.parse_event('{}'))['content']
        self.assertIn('UNKNOWN_MALWARE_EVENT', message)
        self.assertIn('not supplied', message)

    def test_mapping_payloads(self):
        event = alert.normalize({'malicious_files': {'example-user': ['/home/example-user/bad.php'],
                                                     'another-user': ['/home/another-user/bad.php']}})
        self.assertEqual({r['user'] for r in event['records']}, {'example-user', 'another-user'})
        event = alert.normalize({'malicious_files': {'/home/example-user/bad.php': 'EXAMPLE-SIGNATURE'}})
        self.assertEqual(event['records'][0]['signature'], 'EXAMPLE-SIGNATURE')

    def test_scan_type_is_not_mistaken_for_a_malware_signature(self):
        events = []
        for event_type, kind in zip(alert.EVENTS, ('on-demand', 'user')):
            event = alert.normalize({'event_id': event_type, 'type': kind, 'scan_id': 'example-scan',
                                     'file_path': '/home/example-user/bad.php'})
            self.assertEqual(event['records'][0]['signature'], '')
            events.append(event)
        self.assertEqual(alert.fingerprints(events[0]), alert.fingerprints(events[1]))

    def test_redaction_message_limits_and_arbitrary_fields_excluded(self):
        raw = example()
        raw['unrelated-secret'] = 'must-never-forward'
        raw['malicious_files'] = [{'path': '/home/example-user/' + 'x' * 1000,
                                   'signature': 'https://discord.com/api/webhooks/123/synthetic_test_value @everyone\n\x1b'}] * 30
        message = alert.payload(alert.normalize(raw))
        self.assertLessEqual(len(message['content']), 2000)
        self.assertNotIn('synthetic_test_value', message['content'])
        self.assertNotIn('must-never-forward', message['content'])
        self.assertNotIn('\x1b', message['content'])
        self.assertNotIn('@everyone', message['content'])

    def test_simulations_send_both_without_using_cache_or_scan(self):
        with patch.object(sys, 'argv', ['alert.py', '--test-event', 'both']), \
             patch.object(Path, 'read_text', return_value='synthetic-webhook'), \
             patch.object(alert, 'send') as send, patch.object(alert, 'deliver') as deliver, \
             patch.object(sys, 'stdout', new_callable=io.StringIO):
            self.assertEqual(alert.main(), 0)
        self.assertEqual(send.call_count, 2)
        deliver.assert_not_called()
        for call, event_type in zip(send.call_args_list, alert.EVENTS):
            self.assertIn(event_type, call.args[0]['content'])
            self.assertIn('SIMULATED TEST', call.args[0]['content'])

    def test_simulate_each_event_individually(self):
        for event_type in alert.EVENTS:
            with self.subTest(event=event_type), patch.object(sys, 'argv', ['alert.py', '--test-event', event_type]), \
                 patch.object(Path, 'read_text', return_value='synthetic-webhook'), \
                 patch.object(alert, 'send') as send, patch.object(sys, 'stdout', new_callable=io.StringIO):
                self.assertEqual(alert.main(), 0)
                send.assert_called_once()
                self.assertIn(event_type, send.call_args.args[0]['content'])

    def test_unrelated_event_is_ignored(self):
        stdin = Mock(buffer=io.BytesIO(b'{"event_id":"USER_SCAN_FINISHED"}'))
        with patch.object(sys, 'argv', ['alert.py']), patch.object(sys, 'stdin', stdin), \
             patch.object(Path, 'read_text', return_value='synthetic-webhook'), patch.object(alert, 'deliver') as deliver:
            self.assertEqual(alert.main(), 0)
        deliver.assert_not_called()


class DedupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.state.chmod(0o700)
        self.send = Mock()

    def deliver(self, event, now=1000):
        return alert.deliver(alert.normalize(event), 'synthetic-webhook', self.state, self.send, now)

    def test_both_event_types_same_detection_send_once(self):
        self.assertTrue(self.deliver(example()))
        self.assertFalse(self.deliver(example(alert.EVENTS[1])))
        self.send.assert_called_once()
        self.assertEqual((self.state / 'deliveries.sqlite3').stat().st_mode & 0o777, 0o600)

    def test_distinct_files_users_signatures_hashes_and_scans_are_delivered(self):
        events = [example(), example(path='/home/example-user/second.php'),
                  example(path='/home/another-user/second.php'), example(scan_id='another-scan')]
        for signature, checksum in (('EXAMPLE-A', 'a'), ('EXAMPLE-B', 'a'), ('EXAMPLE-B', 'b')):
            raw = example()
            raw['malicious_files'] = [{'path': '/home/example-user/bad.php', 'signature': signature, 'sha256': checksum}]
            events.append(raw)
        for event in events:
            self.assertTrue(self.deliver(event))
        self.assertEqual(self.send.call_count, len(events))

    def test_overlapping_batch_with_new_finding_is_not_lost(self):
        self.deliver(example())
        new = example(alert.EVENTS[1])
        new['malicious_files'].append('/home/example-user/new-infection.php')
        self.assertTrue(self.deliver(new))
        self.assertIn('new-infection.php', self.send.call_args.args[0]['content'])
        self.assertEqual(self.send.call_count, 2)

    def test_expiry_and_missing_identity_fail_open(self):
        self.deliver(example())
        self.assertTrue(self.deliver(example(), 1000 + alert.DEDUP_SECONDS))
        self.assertTrue(self.deliver({}))
        self.assertTrue(self.deliver({}))
        self.assertEqual(self.send.call_count, 4)

    def test_failed_delivery_not_cached_or_retried_inside_same_call(self):
        self.send.side_effect = OSError('private-network-value')
        with self.assertRaises(OSError):
            self.deliver(example())
        self.send.assert_called_once()
        self.send.side_effect = None
        self.assertTrue(self.deliver(example()))
        self.assertFalse(self.deliver(example(alert.EVENTS[1])))
        self.assertEqual(self.send.call_count, 2)

    def test_cache_failure_still_delivers(self):
        with patch.object(alert, 'open_cache', side_effect=sqlite3.OperationalError('private-value')), \
             patch.object(sys, 'stderr', new_callable=io.StringIO) as err:
            self.assertTrue(self.deliver(example()))
        self.send.assert_called_once()
        self.assertNotIn('private-value', err.getvalue())

    def test_cache_contains_hashes_not_usernames_paths_or_signatures(self):
        self.deliver(example())
        raw = (self.state / 'deliveries.sqlite3').read_bytes()
        self.assertNotIn(b'example-user', raw)
        self.assertNotIn(b'infected.php', raw)

    def test_untrusted_cache_symlink_is_not_followed(self):
        target = self.state / 'target'
        target.write_text('unchanged')
        (self.state / 'deliveries.sqlite3').symlink_to(target)
        with patch.object(sys, 'stderr', new_callable=io.StringIO):
            self.assertTrue(self.deliver(example()))
        self.assertEqual(target.read_text(), 'unchanged')

    def test_concurrent_events_send_once(self):
        barrier = threading.Barrier(2)
        def sender(*args):
            time.sleep(0.05)
            self.send(*args)
        def deliver(event_type):
            barrier.wait(timeout=5)
            return alert.deliver(alert.normalize(example(event_type)), 'synthetic-webhook', self.state, sender, 1000)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(deliver, alert.EVENTS))
        self.assertEqual(sorted(results), [False, True])
        self.send.assert_called_once()


class RegistrationTests(unittest.TestCase):
    def test_partial_registration_failure_restores_both_original_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'config'
            root.mkdir()
            (root / 'webhook').write_text('synthetic-secret')
            cron = Path(tmp) / 'cron'
            original = {event: {'enabled': False, 'scripts': ['/opt/existing-hook']} for event in alert.EVENTS}
            state = json.loads(json.dumps(original))
            fail_once = True
            def command(args):
                nonlocal state, fail_once
                if args[2] == 'update':
                    state = {event: target['SCRIPT'] for event, target in json.loads(args[3])['rules'].items()}
                    if fail_once:
                        state[alert.EVENTS[1]]['enabled'] = False
                        fail_once = False
                return Mock(stdout=json.dumps({'items': {'rules': {event: {'SCRIPT': target} for event, target in state.items()}}}))
            with patch.object(manage, 'ROOT', root), patch.object(manage, 'CRON', cron), \
                 patch.object(manage, 'command', side_effect=command), \
                 patch.object(os, 'chown'), patch.object(os, 'fchown'):
                transaction = manage.Transaction('agent')
                transaction.notify_changed = True
                with self.assertRaises(RuntimeError):
                    manage.update('agent', {event: manage.registration(target) for event, target in original.items()})
                self.assertTrue(transaction.rollback())
                self.assertEqual(state, original)
                self.assertEqual((root / 'webhook').read_text(), 'synthetic-secret')

    def test_verifier_fails_for_disabled_user_event_then_passes_after_repair(self):
        old = {alert.EVENTS[0]: {'enabled': True, 'scripts': [manage.HOOK, '/opt/another-hook']},
               alert.EVENTS[1]: {'enabled': False, 'scripts': []}}
        with patch.object(manage, 'show', return_value=old), patch.object(sys, 'stdout', new_callable=io.StringIO) as out:
            self.assertEqual(manage.verify('agent'), 1)
            self.assertIn(alert.EVENTS[1] + ': FAIL', out.getvalue())
        repaired = {event: manage.registration(target) for event, target in old.items()}
        with patch.object(manage, 'show', return_value=repaired), patch.object(sys, 'stdout', new_callable=io.StringIO) as out:
            self.assertEqual(manage.verify('agent'), 0)
            self.assertEqual(out.getvalue().count(': OK'), 2)
        self.assertEqual(repaired[alert.EVENTS[0]]['scripts'], ['/opt/another-hook', manage.HOOK])
        self.assertEqual({event: manage.registration(target) for event, target in repaired.items()}, repaired)

    def test_show_missing_event_defaults_and_preserves_unrelated_rules(self):
        config = {'items': {'rules': {'UNRELATED_EVENT': {'SCRIPT': {'enabled': True, 'scripts': ['/opt/other']}}}}}
        result = Mock(stdout=json.dumps(config))
        with patch.object(manage, 'command', return_value=result):
            actual = manage.show('agent')
        self.assertEqual(actual, {event: {'enabled': False, 'scripts': []} for event in alert.EVENTS})

    def test_removal_handles_both_events_without_disabling_other_hooks(self):
        old = {event: {'enabled': True, 'scripts': [manage.HOOK, '/opt/another-hook']} for event in alert.EVENTS}
        removed = {event: manage.registration(target, remove=True) for event, target in old.items()}
        self.assertTrue(all(t == {'enabled': True, 'scripts': ['/opt/another-hook']} for t in removed.values()))


if __name__ == '__main__':
    unittest.main()
