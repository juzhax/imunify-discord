"""Offline regression tests; never contact Discord or require ImunifyAV/root."""
import copy
import io
import json
import os
import stat
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import alert
import manage
import scan


class ProjectTests(unittest.TestCase):
    def test_state_paths_reject_unsafe_permissions_ownership_and_types(self):
        for mode, uid in ((stat.S_IFREG | 0o660, 0), (stat.S_IFREG | 0o644, 1000),
                          (stat.S_IFIFO | 0o600, 0), (stat.S_IFLNK | 0o777, 0)):
            info = os.stat_result((mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))
            with self.subTest(mode=mode, uid=uid), patch.object(Path, 'lstat', return_value=info):
                with self.assertRaises(RuntimeError):
                    manage.validate_state_path(Path('/example/config'))
        safe = os.stat_result((stat.S_IFREG | 0o640, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        with patch.object(Path, 'lstat', return_value=safe):
            manage.validate_state_path(Path('/example/config'))

    def test_nested_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            link = root / 'nested-link'
            link.symlink_to('/etc/passwd')
            # Walk a trusted root directory regardless of the test runner uid.
            original_lstat = Path.lstat
            def root_owned(path):
                info = original_lstat(path)
                fields = list(info)
                fields[4] = 0
                return os.stat_result(fields)
            with patch.object(Path, 'lstat', root_owned):
                with self.assertRaisesRegex(RuntimeError, 'symbolic link'):
                    manage.validate_state_path(root)

    def test_delivery_disables_proxies_and_redirects(self):
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.status = 204
        opener = unittest.mock.MagicMock()
        opener.open.return_value = response
        with patch.object(alert.urllib.request, 'build_opener', return_value=opener) as build:
            alert.send(alert.payload(test=True), 'https://discord.com/api/webhooks/123/synthetic_test_value')
        handlers = build.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsNone(handlers[1].redirect_request(None, None, 302, '', {}, 'https://example.invalid'))
        self.assertEqual(opener.open.call_args.kwargs['timeout'], 20)

    def test_webhook_rejects_exfiltration_and_queries(self):
        for url in ('http://discord.com/api/webhooks/1/x',
                    'https://discord.com.evil.example/api/webhooks/1/x',
                    'https://discord.com/api/webhooks/1/x?secret=1',
                    'https://user@discord.com/api/webhooks/1/x', 'file:///etc/passwd'):
            with self.assertRaises(ValueError):
                alert.validate_webhook(url)

    def test_hostname_mentions_and_private_event(self):
        with patch.object(alert.socket, 'gethostname', return_value='host.example.invalid'):
            data = alert.payload({'secret': 'must-not-be-forwarded'})
        self.assertEqual(data['username'], 'host.example.invalid')
        self.assertEqual(data['allowed_mentions'], {'parse': []})
        self.assertNotIn('must-not-be-forwarded', json.dumps(data))
        self.assertIn('No scan was started', alert.payload(test=True)['content'])

    def test_network_failure_redacts_url(self):
        with patch.object(sys, 'argv', ['alert.py', '--test']), \
             patch.object(Path, 'read_text', return_value='secret-url'), \
             patch.object(alert, 'send', side_effect=RuntimeError('secret-url')), \
             patch.object(sys, 'stderr', new_callable=io.StringIO) as output:
            self.assertEqual(alert.main(), 1)
            self.assertNotIn('secret-url', output.getvalue())

    def test_cron_validation(self):
        for valid in ('0 3 * * *', '0 3 * * 1', '*/30 1-4 * * 0,6'):
            scan.validate_cron(valid)
        for invalid in ('60 3 * * *', '* 24 * * *', '* * 0 * *', '@daily',
                        '* * * * *\nroot evil', '* * * * */0', '* * * * 7-1'):
            with self.assertRaises(ValueError):
                scan.validate_cron(invalid)

    def test_config_is_data_and_scan_is_detection_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / 'config.env'
            config.write_text('SCAN_CRON=0 3 * * *\nSCAN_PATH=' + tmp + '\nSCAN_CPU=2\nSCAN_IO=3\n')
            parsed = scan.read_config(config)
            with patch.object(scan.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
                scan.run(parsed, '/usr/bin/imunify-antivirus')
            args = run.call_args.args[0]
            self.assertEqual(args[1:4], ['malware', 'on-demand', 'start'])
            self.assertNotIn('cleanup', args)
            config.write_text(config.read_text() + 'EVIL=$(touch /tmp/bad)\n')
            with self.assertRaises(ValueError):
                scan.read_config(config)

    def test_registration_idempotent_and_preserves_others(self):
        old = {'scripts': ['/opt/other', manage.HOOK, manage.HOOK], 'enabled': False}
        first = manage.registration(old)
        self.assertEqual(manage.registration(first), first)
        self.assertEqual(first['scripts'], ['/opt/other', manage.HOOK])
        self.assertEqual(manage.registration(old, remove=True), {'scripts': ['/opt/other'], 'enabled': False})
        self.assertEqual(old['scripts'].count(manage.HOOK), 2)

    def test_uninstall_empty_target(self):
        self.assertEqual(manage.registration({'scripts': [manage.HOOK], 'enabled': True}, remove=True),
                         {'scripts': [], 'enabled': False})
        untouched = {'scripts': [], 'enabled': True}
        self.assertEqual(manage.registration(untouched, remove=True), untouched)

    def test_cli_uses_partial_update_and_checks_readback(self):
        target = {'enabled': True, 'scripts': ['/opt/other', manage.HOOK]}
        calls = []
        def fake(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, json.dumps({'items': {'rules': {manage.EVENT: {'SCRIPT': target}}}}))
        with patch.object(manage, 'command', side_effect=fake):
            manage.update('/usr/bin/imunify-antivirus', target)
        self.assertEqual(calls[0][1:3], ['notifications-config', 'update'])
        self.assertEqual(json.loads(calls[0][3]), {'rules': {manage.EVENT: {'SCRIPT': target}}})
        with patch.object(manage, 'command', side_effect=fake), \
             patch.object(manage, 'show', return_value={'enabled': False, 'scripts': []}):
            with self.assertRaises(RuntimeError):
                manage.update('agent', target)

    def test_legacy_cron_migration(self):
        text = '# keep\n0 3 * * * /usr/bin/imunify-antivirus malware on-demand start --path=/home\n0 1 * * * /usr/bin/backup\n'
        migrated = manage.legacy_crontab(text)
        self.assertEqual(migrated, '# keep\n0 1 * * * /usr/bin/backup\n')
        self.assertEqual(manage.legacy_crontab(migrated), migrated)
        with self.assertRaises(RuntimeError):
            manage.legacy_crontab('0 3 * * * flock /tmp/x imunify-antivirus malware on-demand start --path /home\n')

    def test_rollback_restores_files_cron_and_registration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'config'
            root.mkdir()
            (root / 'webhook').write_text('existing-secret')
            (root / 'alert.py').write_text('legacy-script')
            cron = Path(tmp) / 'cron'
            cron.write_text('legacy cron\n')
            target = {'enabled': False, 'scripts': ['/opt/other']}
            with patch.object(manage, 'ROOT', root), patch.object(manage, 'CRON', cron), \
                 patch.object(manage, 'show', return_value=target), \
                 patch.object(manage, 'update') as update, \
                 patch.object(os, 'chown'), patch.object(os, 'fchown'):
                transaction = manage.Transaction('agent')
                (root / 'webhook').write_text('changed')
                (root / 'scan.py').write_text('new')
                cron.write_text('new cron')
                transaction.notify_changed = True
                self.assertTrue(transaction.rollback())
                self.assertEqual((root / 'webhook').read_text(), 'existing-secret')
                self.assertEqual((root / 'alert.py').read_text(), 'legacy-script')
                self.assertFalse((root / 'scan.py').exists())
                self.assertEqual(cron.read_text(), 'legacy cron\n')
                update.assert_called_once_with('agent', target)


class DeploymentTests(unittest.TestCase):
    def exercise_deployment(self, fail=False):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / 'config'
            root.mkdir()
            # Intentionally synthetic credentials, never contact Discord.
            secret = 'https://discord.com/api/webhooks/123/synthetic_test_value\n'
            (root / 'webhook').write_text(secret)
            (root / 'alert.py').write_text('old script')
            config = 'SCAN_CRON=0 3 * * 1\nSCAN_PATH=' + tmp + '\nSCAN_CPU=1\nSCAN_IO=3\n'
            (root / 'config.env').write_text(config)
            cron_dir = base / 'cron.d'
            cron_dir.mkdir()
            cron = cron_dir / 'imunify-discord'
            cron.write_text('old cron\n')
            state = {'target': {'enabled': True, 'scripts': ['/opt/other', manage.HOOK, manage.HOOK]}}
            original_target = copy.deepcopy(state['target'])
            def fake_command(args, **kwargs):
                if args[1:3] == ['notifications-config', 'show']:
                    return subprocess.CompletedProcess(args, 0, json.dumps({'items': {'rules': {
                        manage.EVENT: {'SCRIPT': state['target']}}}}), '')
                if args[1:3] == ['notifications-config', 'update']:
                    state['target'] = json.loads(args[3])['rules'][manage.EVENT]['SCRIPT']
                    return subprocess.CompletedProcess(args, 0, '', '')
                if args == ['crontab', '-l']:
                    return subprocess.CompletedProcess(args, 0, '0 1 * * * /usr/bin/backup\n', '')
                raise AssertionError(args)
            user = type('User', (), {'pw_name': '_imunify', 'pw_uid': 100, 'pw_gid': 100})()
            args = type('Args', (), {'notification_user': None, 'update': True})()
            original_write = manage.write
            failed = False
            def maybe_fail(path, *args, **kwargs):
                nonlocal failed
                if fail and path == cron and not failed:
                    failed = True
                    raise OSError('simulated disk write failure after registration')
                return original_write(path, *args, **kwargs)
            with patch.object(manage, 'ROOT', root), patch.object(manage, 'CRON', cron), \
                 patch.object(manage, 'command', side_effect=fake_command), \
                 patch.object(manage, 'identity', return_value=(user, 100, [100])), \
                 patch.object(manage, 'check_access'), \
                 patch.object(manage.shutil, 'which', return_value='/usr/bin/flock'), \
                 patch.object(manage, 'write', side_effect=maybe_fail), \
                 patch.object(os, 'chown'), patch.object(os, 'fchown'):
                for _ in range(1 if fail else 2):
                    transaction = manage.Transaction('agent')
                    if fail:
                        with self.assertRaises(OSError):
                            manage.deploy(args, 'agent', transaction)
                        self.assertTrue(transaction.rollback())
                    else:
                        manage.deploy(args, 'agent', transaction)
                        manage.shutil.rmtree(transaction.backup)
                self.assertEqual((root / 'webhook').read_text(), secret)
                self.assertEqual((root / 'config.env').read_text(), config)
                if fail:
                    self.assertEqual(state['target'], original_target)
                    self.assertEqual((root / 'alert.py').read_text(), 'old script')
                    self.assertEqual(cron.read_text(), 'old cron\n')
                    self.assertFalse((root / 'scan.py').exists())
                else:
                    self.assertEqual(state['target']['scripts'], ['/opt/other', manage.HOOK])
                    self.assertEqual(cron.read_text().count(' root '), 1)
                    self.assertIn('0 3 * * 1 root', cron.read_text())
                    self.assertEqual((root / 'webhook').stat().st_mode & 0o777, 0o640)
                    self.assertEqual((root / 'alert.py').stat().st_mode & 0o777, 0o750)

    def test_repeat_update_preserves_secret_config_and_other_hooks(self):
        self.exercise_deployment()

    def test_install_failure_after_registration_rolls_back(self):
        self.exercise_deployment(fail=True)


if __name__ == '__main__':
    unittest.main()
