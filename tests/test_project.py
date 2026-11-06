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

LEGACY_JOB = ('0 3 * * * root /usr/bin/flock -n /run/imunifyav-nightly.lock '
              '/usr/bin/imunify-antivirus malware on-demand start --path /home '
              '--no-follow-symlinks --intensity-cpu 2 --intensity-io 2 '
              '>> /var/log/imunifyav-nightly.log 2>&1\n')


class ProjectTests(unittest.TestCase):
    def test_explicit_migration_preserves_unrelated_entries_and_is_repeatable(self):
        config = {'SCAN_CRON': '0 3 * * *', 'SCAN_PATH': '/home', 'SCAN_CPU': '2', 'SCAN_IO': '2'}
        remaining = '# existing comment\n0 1 * * * root /usr/bin/backup\n'
        result = manage.migrate_cron_text(remaining + LEGACY_JOB, config, '/usr/bin/imunify-antivirus')
        self.assertEqual(result, remaining)
        self.assertEqual(manage.migrate_cron_text(result, config, '/usr/bin/imunify-antivirus'), result)

    def test_explicit_migration_rejects_different_settings_and_shell_commands(self):
        config = {'SCAN_CRON': '0 3 * * *', 'SCAN_PATH': '/home', 'SCAN_CPU': '2', 'SCAN_IO': '2'}
        for job in (LEGACY_JOB.replace('0 3', '0 4'), LEGACY_JOB.replace('--intensity-cpu 2', '--intensity-cpu 7'),
                    LEGACY_JOB.replace('--no-follow-symlinks', '--follow-symlinks'),
                    LEGACY_JOB.rstrip() + '; /usr/bin/other\n', LEGACY_JOB + LEGACY_JOB,
                    LEGACY_JOB.replace('/var/log/imunifyav-nightly.log', '/tmp/untrusted.log')):
            with self.subTest(job=job), self.assertRaises(RuntimeError):
                manage.migrate_cron_text(job, config, '/usr/bin/imunify-antivirus')

    def test_explicit_migration_rejects_paths_outside_cron_directory(self):
        for value in ('/tmp/legacy', 'legacy', '/etc/cron.d/../legacy', '/etc/cron.d/imunify-discord', '/etc/cron.d/..'):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                manage.plan_cron_migration(value, {}, 'agent')

    def test_secure_prompt_opens_real_nonseekable_terminal(self):
        # Isolate terminal/session side effects from the test runner itself.
        code = '''
import os
import signal
from unittest.mock import patch
import manage
signal.signal(signal.SIGHUP, signal.SIG_IGN)
master, slave = os.openpty()
try:
    with patch.object(manage.getpass, 'getpass', return_value='https://discord.com/api/webhooks/123/synthetic_test_value') as prompt:
        value = manage.prompt_webhook(os.ttyname(slave))
        assert value.endswith('/synthetic_test_value')
        assert prompt.call_args.kwargs['stream'].mode == 'w'
finally:
    os.close(master)
    os.close(slave)
'''
        result = subprocess.run([sys.executable, '-c', code], cwd=Path(manage.__file__).parent,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')

    def test_prompt_requires_hidden_input_and_valid_url(self):
        with patch('manage.open', create=True, side_effect=OSError('private-value')):
            with self.assertRaisesRegex(RuntimeError, 'interactive terminal'):
                manage.prompt_webhook()
        with patch('manage.open', create=True, return_value=io.StringIO()), \
             patch.object(manage.getpass, 'getpass', side_effect=manage.getpass.GetPassWarning('private-value')):
            with self.assertRaisesRegex(RuntimeError, 'input must remain hidden'):
                manage.prompt_webhook()
        with patch('manage.open', create=True, return_value=io.StringIO()), \
             patch.object(manage.getpass, 'getpass', return_value='invalid-private-value'):
            with self.assertRaisesRegex(RuntimeError, 'Invalid webhook format'):
                manage.prompt_webhook()

    def test_safe_diagnostics_include_stage_without_exception_values(self):
        for error in (OSError(13, 'private-value'), ValueError('private-value')):
            message = manage.failure_message(error, 'secure webhook prompt')
            self.assertIn('secure webhook prompt', message)
            self.assertIn(type(error).__name__, message)
            self.assertNotIn('private-value', message)
        self.assertIn('errno=13', manage.failure_message(OSError(13, 'private-value'), 'backup'))

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
            data = alert.payload(alert.normalize({'secret': 'must-not-be-forwarded'}))
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
            self.assertIn('--no-follow-symlinks', args)
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
        targets = {event: {'enabled': True, 'scripts': ['/opt/other', manage.HOOK]} for event in manage.EVENTS}
        calls = []
        def fake(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, json.dumps({'items': {'rules': {
                event: {'SCRIPT': target} for event, target in targets.items()}}}))
        with patch.object(manage, 'command', side_effect=fake):
            manage.update('/usr/bin/imunify-antivirus', targets)
        self.assertEqual(calls[0][1:3], ['notifications-config', 'update'])
        self.assertEqual(json.loads(calls[0][3]), {'rules': {event: {'SCRIPT': target} for event, target in targets.items()}})
        broken = copy.deepcopy(targets)
        broken[manage.EVENTS[1]]['enabled'] = False
        with patch.object(manage, 'command', side_effect=fake), patch.object(manage, 'show', return_value=broken):
            with self.assertRaises(RuntimeError):
                manage.update('agent', targets)

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
    def exercise_deployment(self, fail=False, prompt=False, migrate=False, preserve_cron=False):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / 'config'
            root.mkdir()
            # Intentionally synthetic credentials, never contact Discord.
            secret = 'https://discord.com/api/webhooks/123/synthetic_test_value\n'
            (root / 'webhook').write_text(secret.rstrip('\n'))
            if prompt:
                (root / 'webhook').unlink()
            (root / 'alert.py').write_text('old script')
            config = 'SCAN_CRON=0 3 * * 1\nSCAN_PATH=' + tmp + '\nSCAN_CPU=1\nSCAN_IO=3\n'
            (root / 'config.env').write_text(config)
            cron_dir = base / 'cron.d'
            cron_dir.mkdir()
            cron = cron_dir / 'imunify-discord'
            cron.write_text('old cron\n')
            legacy = cron_dir / 'legacy-nightly'
            legacy_remaining = '# keep\n0 1 * * * root /usr/bin/backup\n'
            legacy_original = legacy_remaining + LEGACY_JOB.replace('0 3 * * *', '0 3 * * 1').replace('--path /home', '--path ' + tmp).replace('--intensity-cpu 2', '--intensity-cpu 1').replace('--intensity-io 2', '--intensity-io 3')
            if migrate:
                legacy.write_text(legacy_original)
            state = {'target': {event: {'enabled': event == manage.EVENT, 'scripts': ['/opt/other', manage.HOOK, manage.HOOK]} for event in manage.EVENTS}}
            original_target = copy.deepcopy(state['target'])
            def fake_command(args, **kwargs):
                if args[1:3] == ['notifications-config', 'show']:
                    return subprocess.CompletedProcess(args, 0, json.dumps({'items': {'rules': {
                        event: {'SCRIPT': target} for event, target in state['target'].items()}}}), '')
                if args[1:3] == ['notifications-config', 'update']:
                    state['target'] = {event: value['SCRIPT'] for event, value in json.loads(args[3])['rules'].items()}
                    return subprocess.CompletedProcess(args, 0, '', '')
                if args == ['crontab', '-l']:
                    return subprocess.CompletedProcess(args, 0, '0 1 * * * /usr/bin/backup\n', '')
                raise AssertionError(args)
            user = type('User', (), {'pw_name': '_imunify', 'pw_uid': os.getuid(), 'pw_gid': os.getgid()})()
            args = type('Args', (), {'notification_user': None, 'update': not prompt,
                                    'refresh_cron': not preserve_cron, 'migrate_cron': str(legacy) if migrate else None})()
            original_write = manage.write
            failed = False
            def maybe_fail(path, *args, **kwargs):
                nonlocal failed
                if fail and path == cron and not failed:
                    failed = True
                    raise OSError('simulated disk write failure after registration')
                return original_write(path, *args, **kwargs)
            with patch.object(manage, 'ROOT', root), patch.object(manage, 'CRON', cron), \
                 patch.object(manage, 'STATE', base / 'state'), \
                 patch.object(manage, 'command', side_effect=fake_command), \
                 patch.object(manage, 'identity', return_value=(user, 100, [100])), \
                 patch.object(manage, 'check_access'), \
                 patch.object(manage, 'validate_state_path'), \
                 patch.object(manage, 'prompt_webhook', return_value=secret.strip()) as prompt_call, \
                 patch.object(manage.shutil, 'which', return_value='/usr/bin/flock'), \
                 patch.object(manage, 'write', side_effect=maybe_fail) as write_calls, \
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
                self.assertEqual((root / 'webhook').read_text(), secret if prompt else secret.rstrip('\n'))
                self.assertEqual((root / 'config.env').read_text(), config)
                self.assertEqual(prompt_call.call_count, 1 if prompt else 0)
                if fail:
                    self.assertEqual(state['target'], original_target)
                    self.assertEqual((root / 'alert.py').read_text(), 'old script')
                    self.assertEqual(cron.read_text(), 'old cron\n')
                    self.assertFalse((root / 'scan.py').exists())
                    if migrate:
                        self.assertEqual(legacy.read_text(), legacy_original)
                else:
                    for target in state['target'].values():
                        self.assertTrue(target['enabled'])
                        self.assertEqual(target['scripts'], ['/opt/other', manage.HOOK])
                    if preserve_cron:
                        self.assertEqual(cron.read_text(), 'old cron\n')
                        self.assertNotIn(cron, [call.args[0] for call in write_calls.call_args_list])
                        self.assertNotIn(root / 'webhook', [call.args[0] for call in write_calls.call_args_list])
                    else:
                        self.assertEqual(cron.read_text().count(' root '), 1)
                        self.assertIn('0 3 * * 1 root', cron.read_text())
                    self.assertEqual((root / 'webhook').stat().st_mode & 0o777, 0o640)
                    self.assertEqual((root / 'alert.py').stat().st_mode & 0o777, 0o750)
                    if migrate:
                        self.assertEqual(legacy.read_text(), legacy_remaining)

    def test_update_repairs_both_events_without_rewriting_cron_or_webhook(self):
        self.exercise_deployment(preserve_cron=True)

    def test_repeat_update_preserves_secret_config_and_other_hooks(self):
        self.exercise_deployment()

    def test_install_failure_after_registration_rolls_back(self):
        self.exercise_deployment(fail=True)

    def test_install_without_webhook_prompts_once_then_reuses_secret(self):
        self.exercise_deployment(prompt=True)

    def test_install_migrates_selected_cron_and_preserves_config(self):
        self.exercise_deployment(migrate=True)

    def test_failed_install_restores_selected_cron(self):
        self.exercise_deployment(fail=True, migrate=True)


if __name__ == '__main__':
    unittest.main()
