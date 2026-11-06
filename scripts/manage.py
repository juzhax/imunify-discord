#!/usr/bin/python3
"""Privileged local deployment manager; no network downloads or shell evaluation."""
import argparse
import copy
import fcntl
import getpass
import grp
import json
import os
import pwd
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import warnings
from pathlib import Path

from alert import validate_webhook
from scan import read_config, validate_cron

ROOT = Path('/etc/imunify-discord')
CRON = Path('/etc/cron.d/imunify-discord')
HOOK = str(ROOT / 'alert.py')  # Keep the established notification path for compatible upgrades.
EVENT = 'CUSTOM_SCAN_MALWARE_FOUND'
SOURCE = Path(__file__).resolve().parent.parent


def command(args, ok=(0,)):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('Command failed or timed out: ' + Path(args[0]).name) from None
    if result.returncode not in ok:
        # CLI output may contain third-party configuration; never echo it.
        raise RuntimeError('Command failed: ' + ' '.join(args[:3]))
    return result


def show(agent):
    try:
        data = json.loads(command([agent, 'notifications-config', 'show', '--json']).stdout)
        rules = data.get('items', data)['rules']
        target = rules.get(EVENT, {}).get('SCRIPT', {'enabled': False, 'scripts': []})
        if not isinstance(target.get('enabled'), bool) or not isinstance(target.get('scripts'), list):
            raise ValueError()
        if any(not isinstance(x, str) or not x.startswith('/') for x in target['scripts']):
            raise ValueError()
        return copy.deepcopy(target)
    except (AttributeError, KeyError, TypeError, ValueError):
        raise RuntimeError('Unsupported notifications-config JSON schema; no changes made.') from None


def update(agent, target):
    data = json.dumps({'rules': {EVENT: {'SCRIPT': target}}})
    # Payload contains executable paths and booleans only, never the webhook.
    command([agent, 'notifications-config', 'update', data])
    actual = show(agent)
    if any(actual.get(k) != v for k, v in target.items()):
        raise RuntimeError('Notification update did not persist as requested.')


def registration(old, remove=False):
    new = copy.deepcopy(old)
    if remove and HOOK not in old['scripts']:
        return new
    scripts = [p for p in old['scripts'] if p != HOOK]
    if not remove:
        scripts.append(HOOK)
    new['scripts'] = scripts
    new['enabled'] = bool(scripts) if remove else True
    # Preserve another administrator's disabled target on uninstall.
    if remove and scripts:
        new['enabled'] = old['enabled']
    return new


def write(path, data, mode, gid=0):
    if path.is_symlink():
        raise RuntimeError('Refusing symbolic link: ' + str(path))
    fd, name = tempfile.mkstemp(prefix='.imunify-discord-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data if isinstance(data, bytes) else data.encode())
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), 0, gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def identity(name):
    try:
        user = pwd.getpwnam(name or '_imunify')
    except KeyError:
        raise RuntimeError('Notification user not found. Supply --notification-user NAME after verifying the notifier identity.') from None
    try:
        gid = grp.getgrnam('_imunify').gr_gid
    except KeyError:
        gid = user.pw_gid
    groups = os.getgrouplist(user.pw_name, user.pw_gid)
    if gid not in groups and user.pw_uid != 0:
        raise RuntimeError('Notification user does not belong to the configuration access group.')
    return user, gid, groups


def check_access(user, groups):
    def drop():
        os.setgroups(groups)
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)
    # A real access check as the notifier identity, including parent traversal.
    result = subprocess.run(['/usr/bin/python3', '-I', '-c',
                             'import os; from pathlib import Path; '
                             'Path("/etc/imunify-discord/webhook").read_bytes(); '
                             'assert os.access("/etc/imunify-discord/alert.py", os.X_OK)'],
                            preexec_fn=drop, capture_output=True, timeout=10)
    if result.returncode:
        raise RuntimeError('Notification user cannot read webhook or execute alert.py.')


def legacy_crontab(text):
    """Migrate only the simple legacy /home job. Fail closed on ambiguity."""
    kept = []
    for line in text.splitlines():
        if line.lstrip().startswith('#') or not line.strip():
            kept.append(line)
            continue
        if 'imunify-antivirus' in line and 'on-demand' in line and '/home' in line:
            parts = line.split(None, 5)
            try:
                words = shlex.split(parts[5]) if len(parts) == 6 else []
            except ValueError:
                words = []
            # Only a plain command with optional stdout/stderr redirection.
            if words and Path(words[0]).name == 'imunify-antivirus':
                tail = words[1:]
                for suffix in (['>/dev/null', '2>&1'], ['>', '/dev/null', '2>&1']):
                    if tail[-len(suffix):] == suffix:
                        tail = tail[:-len(suffix)]
                if tail in (['malware', 'on-demand', 'start', '--path', '/home'],
                            ['malware', 'on-demand', 'start', '--path=/home']):
                    continue
            raise RuntimeError('Unmanaged /home scan in root crontab. Remove or migrate that job before installing.')
        kept.append(line)
    return '\n'.join(kept) + ('\n' if kept else '')


def migrate_cron_text(text, config, agent):
    """Remove only a recognized scan equivalent to the new managed job."""
    kept = []
    found = 0
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith('#') or 'imunify-antivirus' not in line or 'on-demand' not in line:
            kept.append(line)
            continue
        try:
            fields = line.split(None, 6)
            schedule = ' '.join(fields[:5])
            validate_cron(schedule)
            if len(fields) != 7 or fields[5] != 'root' or schedule != ' '.join(config['SCAN_CRON'].split()):
                raise ValueError()
            words = shlex.split(fields[6])
            if len(words) >= 3 and words[-3] == '>>' and words[-1] == '2>&1':
                log = Path(words[-2])
                if not log.is_absolute() or log.parent != Path('/var/log'):
                    raise ValueError()
                words = words[:-3]
            for suffix in (['>/dev/null', '2>&1'], ['>', '/dev/null', '2>&1']):
                if words[-len(suffix):] == suffix:
                    words = words[:-len(suffix)]
            if words[:2] == ['/usr/bin/flock', '-n']:
                if Path(words[2]).parent not in (Path('/run'), Path('/var/run')):
                    raise ValueError()
                words = words[3:]
            if not words or words[0] not in (agent, '/usr/bin/imunify-antivirus'):
                raise ValueError()
            expected = ['malware', 'on-demand', 'start', '--path', config['SCAN_PATH'],
                        '--no-follow-symlinks', '--intensity-cpu', config['SCAN_CPU'],
                        '--intensity-io', config['SCAN_IO']]
            if words[1:] != expected:
                raise ValueError()
        except (IndexError, ValueError):
            raise RuntimeError('Legacy cron command or settings differ from the managed scan. No migration performed; review config.env and the selected cron file.') from None
        found += 1
    if found > 1:
        raise RuntimeError('Multiple scan entries in selected cron file; review them before migration.')
    return ''.join(kept)


def plan_cron_migration(value, config, agent):
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute() or path.parent != CRON.parent or path == CRON or path.name in ('.', '..'):
        raise RuntimeError('--migrate-cron must name another file directly inside /etc/cron.d.')
    if path.is_dir() and not path.is_symlink():
        raise RuntimeError('Selected legacy cron path must be a regular file.')
    validate_state_path(path)
    if not path.is_file():
        raise RuntimeError('Selected legacy cron file does not exist or is not a regular file.')
    original = path.read_bytes().decode('utf-8')
    replacement = migrate_cron_text(original, config, agent)
    return path, original, replacement


class Transaction:
    def __init__(self, agent):
        self.agent = agent
        self.old_target = show(agent)
        self.backup = Path(tempfile.mkdtemp(prefix='imunify-discord-rollback-'))
        self.cron_changed = False
        self.notify_changed = False
        self.legacy_changed = False
        self.legacy_path = None
        self.had_root = ROOT.exists()
        self.root_stat = ROOT.stat() if self.had_root else None
        self.owners = {}
        if self.had_root:
            self.owners = {str(p.relative_to(ROOT)): (p.lstat().st_uid, p.lstat().st_gid)
                           for p in [ROOT] + list(ROOT.rglob('*'))}
            shutil.copytree(ROOT, self.backup / 'config', symlinks=True)
        if CRON.exists():
            shutil.copy2(CRON, self.backup / 'cron')
            self.cron_stat = CRON.stat()
        else:
            self.cron_stat = None

    def rollback(self):
        errors = []
        if self.notify_changed:
            try:
                update(self.agent, self.old_target)
            except Exception:
                errors.append('notification registration')
        try:
            if ROOT.exists():
                shutil.rmtree(ROOT)
            if self.had_root:
                shutil.copytree(self.backup / 'config', ROOT, symlinks=True)
                for path in [ROOT] + list(ROOT.rglob('*')):
                    # copytree preserves mode but not ownership.
                    uid, gid = self.owners[str(path.relative_to(ROOT))]
                    os.chown(path, uid, gid, follow_symlinks=False)
                os.chown(ROOT, self.root_stat.st_uid, self.root_stat.st_gid)
                os.chmod(ROOT, stat.S_IMODE(self.root_stat.st_mode))
            if self.cron_stat:
                write(CRON, (self.backup / 'cron').read_bytes(),
                      stat.S_IMODE(self.cron_stat.st_mode), self.cron_stat.st_gid)
            elif CRON.exists():
                CRON.unlink()
        except Exception:
            errors.append('installed files')
        if self.cron_changed:
            try:
                command(['crontab', str(self.backup / 'root-crontab')])
            except Exception:
                errors.append('root crontab')
        if self.legacy_changed:
            try:
                write(self.legacy_path, (self.backup / 'legacy-cron').read_bytes(),
                      stat.S_IMODE(self.legacy_stat.st_mode), self.legacy_stat.st_gid)
            except Exception:
                errors.append('selected legacy cron file')
        if errors:
            print('Error: rollback incomplete for ' + ', '.join(errors) +
                  '. Protected backup retained at ' + str(self.backup), file=sys.stderr)
        else:
            shutil.rmtree(self.backup)
        return not errors


def validate_state_path(path):
    """Never read privileged configuration through links or untrusted paths."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise RuntimeError('Refusing symbolic link: ' + str(path))
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise RuntimeError('Expected regular file or directory: ' + str(path))
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError('Require root ownership and no group/other write permission: ' + str(path))
    if stat.S_ISDIR(info.st_mode):
        for child in path.iterdir():
            validate_state_path(child)


def preflight(install=True):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('Run as root on a Linux server.')
    if sys.version_info < (3, 9):
        raise RuntimeError('Python 3.9 or newer is required.')
    for name in ('flock', 'crontab'):
        if not shutil.which(name):
            raise RuntimeError('Missing dependency: ' + name)
    if install and shutil.which('systemctl'):
        if not any(command(['systemctl', 'is-active', service], ok=(0, 3, 4)).returncode == 0
                   for service in ('crond', 'cron')):
            raise RuntimeError('Cron is not running. Enable crond (AlmaLinux) or cron (Ubuntu).')
    if not Path('/usr/bin/python3').is_file() or not CRON.parent.is_dir():
        raise RuntimeError('Require /usr/bin/python3 and /etc/cron.d (install cron/cronie).')
    agent = shutil.which('imunify-antivirus')
    if not agent:
        raise RuntimeError('Install and configure ImunifyAV first; imunify-antivirus was not found.')
    for path in (ROOT, CRON):
        validate_state_path(path)
    checks = [['notifications-config', 'update', '--help']]
    if install:
        checks.append(['malware', 'on-demand', 'start', '--help'])
    for args in checks:
        help_text = command([agent] + args).stdout
        if args[0] == 'malware' and any(flag not in help_text for flag in ('--path', '--no-follow-symlinks', '--intensity-cpu', '--intensity-io')):
            raise RuntimeError('Installed ImunifyAV lacks required on-demand scan options.')
    return agent


def prompt_webhook(tty_path='/dev/tty'):
    # Text r+ uses BufferedRandom, which requires a seekable file. Terminals
    # are not seekable. getpass reads independently; this stream is output only.
    try:
        with open(tty_path, 'w') as tty, warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            value = getpass.getpass('Discord webhook (hidden): ', stream=tty)
    except (OSError, getpass.GetPassWarning):
        raise RuntimeError('Cannot securely prompt for webhook. Run from an interactive terminal; input must remain hidden.') from None
    try:
        return validate_webhook(value.strip())
    except ValueError:
        raise RuntimeError('Invalid webhook format. Use an HTTPS Discord webhook URL without query parameters.') from None


def failure_message(exc, stage):
    if isinstance(exc, RuntimeError):
        return str(exc)
    if isinstance(exc, KeyboardInterrupt):
        return 'Interrupted during ' + stage + '; rollback attempted if changes were started.'
    # Exception text and tracebacks may contain the webhook. Report only the
    # fixed stage, exception class and numeric errno, never exception values.
    detail = type(exc).__name__
    if isinstance(exc, OSError) and exc.errno is not None:
        detail += ', errno=' + str(exc.errno)
    return 'Operation failed during ' + stage + ' (' + detail + '). Check dependencies, permissions and configuration.'


def deploy(args, agent, transaction):
    transaction.stage = 'notification user validation'
    user, gid, groups = identity(args.notification_user)
    if args.update and (not ROOT.is_dir() or not (ROOT / 'webhook').exists()):
        raise RuntimeError('No existing webhook to preserve. Run install.sh first.')
    transaction.stage = 'configuration validation'
    if (ROOT / 'config.env').exists():
        try:
            config = read_config(ROOT / 'config.env')
        except ValueError as exc:
            raise RuntimeError('Invalid config.env: ' + str(exc)) from None
    else:
        config = read_config(SOURCE / 'config.example.env')
    transaction.stage = 'existing cron validation'
    root_tab = command(['crontab', '-l'], ok=(0, 1))
    if root_tab.returncode == 1 and ('no crontab for' not in root_tab.stderr or root_tab.stdout):
        raise RuntimeError('Unable to read root crontab.')
    migrated = legacy_crontab(root_tab.stdout)
    plan = plan_cron_migration(getattr(args, 'migrate_cron', None), config, agent)
    # Do not silently duplicate a separately managed cron.d scan.
    for path in CRON.parent.iterdir():
        if path == CRON or (plan and path == plan[0]) or not path.is_file():
            continue
        for line in path.read_text(errors='replace').splitlines():
            if not line.lstrip().startswith('#') and 'imunify-antivirus' in line and 'on-demand' in line and '/home' in line:
                raise RuntimeError('Unmanaged /home scan found in ' + str(path) + '; review it, then select it with --migrate-cron FILE.')
    if plan and plan[1] != plan[2]:
        transaction.legacy_path = plan[0]
        transaction.legacy_stat = plan[0].stat()
        write(transaction.backup / 'legacy-cron', plan[1], 0o600)
    existing = ROOT / 'webhook'
    transaction.stage = 'webhook loading'
    if existing.exists():
        try:
            secret = validate_webhook(existing.read_text().strip())
        except ValueError:
            raise RuntimeError('Existing webhook format is invalid; edit /etc/imunify-discord/webhook.') from None
    else:
        transaction.stage = 'secure webhook prompt'
        secret = prompt_webhook()
    transaction.stage = 'runtime file installation'
    ROOT.mkdir(mode=0o750, exist_ok=True)
    os.chown(ROOT, 0, gid)
    os.chmod(ROOT, 0o750)
    write(ROOT / 'webhook', secret + '\n', 0o640, gid)
    if not (ROOT / 'config.env').exists():
        write(ROOT / 'config.env', (SOURCE / 'config.example.env').read_bytes(), 0o640, gid)
    else:
        os.chown(ROOT / 'config.env', 0, gid)
        os.chmod(ROOT / 'config.env', 0o640)
    for script in ('alert.py', 'scan.py'):
        write(ROOT / script, (SOURCE / 'scripts' / script).read_bytes(), 0o750, gid)
    write(ROOT / 'agent', agent + '\n', 0o640, gid)
    transaction.stage = 'notification user access check'
    check_access(user, groups)
    transaction.stage = 'notification registration'
    transaction.notify_changed = True
    update(agent, registration(transaction.old_target))
    if migrated != root_tab.stdout:
        transaction.stage = 'legacy cron migration'
        write(transaction.backup / 'root-crontab', root_tab.stdout, 0o600)
        write(transaction.backup / 'new-crontab', migrated, 0o600)
        transaction.cron_changed = True
        command(['crontab', str(transaction.backup / 'new-crontab')])
    if plan and plan[1] != plan[2]:
        transaction.stage = 'selected legacy cron migration'
        if plan[0].read_bytes().decode('utf-8') != plan[1]:
            raise RuntimeError('Legacy cron file changed during installation; retry after reviewing it.')
        transaction.legacy_changed = True
        write(plan[0], plan[2], stat.S_IMODE(transaction.legacy_stat.st_mode), transaction.legacy_stat.st_gid)
    transaction.stage = 'scan schedule installation'
    cron = ('# Managed by imunify-discord; edit config.env and rerun update.sh.\n'
            'SHELL=/bin/sh\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\n' + config['SCAN_CRON'] +
            ' root /usr/bin/flock -n /run/imunify-discord-scan.lock /usr/bin/python3 -I /etc/imunify-discord/scan.py\n')
    if shutil.which('flock') != '/usr/bin/flock' and not Path('/usr/bin/flock').exists():
        raise RuntimeError('Require flock at /usr/bin/flock.')
    write(CRON, cron, 0o644)


def main():
    os.environ['LC_ALL'] = 'C'  # Stable crontab diagnostics on localized hosts.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'uninstall'))
    parser.add_argument('--update', action='store_true')
    parser.add_argument('--notification-user', help='override verified notifier identity (default: _imunify)')
    parser.add_argument('--migrate-cron', metavar='FILE', help='migrate an equivalent scan from a selected /etc/cron.d file')
    args = parser.parse_args()
    if args.migrate_cron and args.action != 'install':
        parser.error('--migrate-cron is available only for install/update')
    def interrupted(signum, frame):
        raise RuntimeError('Interrupted; installation rollback attempted.')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    transaction = None
    stage = 'dependency and deployment path validation'
    try:
        agent = preflight(install=args.action == 'install')
        stage = 'installer lock acquisition'
        # Serialize installs/updates/uninstalls. Root-owned /run prevents lock replacement.
        fd = os.open('/run/imunify-discord-install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            stage = 'notification and file backup'
            transaction = Transaction(agent)
            try:
                if args.action == 'install':
                    deploy(args, agent, transaction)
                else:
                    transaction.stage = 'notification and runtime removal'
                    transaction.notify_changed = True
                    update(agent, registration(transaction.old_target, remove=True))
                    if CRON.exists():
                        CRON.unlink()
                    # Preserve webhook, administrator configuration and legacy files.
                    for filename in ('alert.py', 'scan.py', 'agent'):
                        path = ROOT / filename
                        if path.exists():
                            path.unlink()
            except BaseException:
                transaction.rollback()
                raise
            shutil.rmtree(transaction.backup)
        print('Installed: notification hook and managed cron job. Configuration preserved.' if args.action == 'install'
              else 'Uninstalled: hook and cron removed. Configuration and webhook retained in /etc/imunify-discord.')
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        # Never print arbitrary exception text: it could contain the webhook.
        message = failure_message(exc, getattr(transaction, 'stage', stage))
        print('Error: ' + message, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
