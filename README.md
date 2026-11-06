# imunify-discord

Minimal Bash + Python integration for ImunifyAV malware alerts in Discord.
Repository: [juzhax/imunify-discord](https://github.com/juzhax/imunify-discord).
MIT licensed; Python standard library only.

- Registers a script on `CUSTOM_SCAN_MALWARE_FOUND`, preserving other scripts and events.
- Submits an on-demand scan of `/home` daily at **03:00 in the server's local timezone**.
- Uses the system hostname as the Discord sender name; disables Discord mentions.
- Never requests cleanup, quarantine, deletion, or changes to ImunifyAV's built-in schedule.
- Reuses existing secrets and configuration; includes rollback and legacy migration support.

## Compatibility and prerequisites

Deployment targets are AlmaLinux 9/10 and Ubuntu, including DirectAdmin, Hestia,
and centminmod servers **with a working ImunifyAV installation**. This project
neither installs ImunifyAV nor makes an unsupported OS/panel combination supported.
Upstream's CLI documentation explicitly describes cPanel/DirectAdmin support;
Hestia, centminmod and individual OS releases require validation on your server.
No live server compatibility testing has been performed in this repository.

Require root, Bash, Python 3.9+ at `/usr/bin/python3`, `flock` from util-linux at
`/usr/bin/flock`, a running cron daemon with `/etc/cron.d` support, `crontab`,
working DNS, a trusted system CA store, and outbound HTTPS to Discord.
The installer validates the installed agent's CLI help and notification JSON.
On systems using systemd, it checks that `cron` or `crond` is active.

```bash
# AlmaLinux (install ImunifyAV separately)
sudo dnf install git python3 util-linux cronie ca-certificates
sudo systemctl enable --now crond

# Ubuntu (install ImunifyAV separately)
sudo apt-get install git python3 util-linux cron ca-certificates
sudo systemctl enable --now cron
```

The notifier normally runs as `_imunify`. The installer uses group `_imunify`
when present, otherwise the notifier user's primary group. It verifies group
membership and performs a real read/execute access check as that user. If your
installation uses another identity, verify it first, then pass
`--notification-user NAME` to install/update. This option checks permissions;
it does not change ImunifyAV's execution identity.

## Install and test

Use the same directory layout on each server:

| Directory | Purpose |
| --- | --- |
| `/opt/imunify-discord` | Root-owned Git checkout: source, installer, updates, tests and documentation |
| `/etc/imunify-discord` | Webhook, configuration and installed runtime scripts managed by the installer |
| `/etc/cron.d/imunify-discord` | Managed scan schedule |

Keep an existing `/etc/imunify-discord` directory in place. Clone the source into
`/opt/imunify-discord`; the installer reuses the existing webhook and preserves
configuration. Keep webhook secrets outside the Git checkout. Commands below
use `sudo`; when already logged in as root, omit `sudo`.

1. Clone and inspect the project in `/opt`:

   ```bash
   sudo git clone https://github.com/juzhax/imunify-discord.git /opt/imunify-discord
   cd /opt/imunify-discord
   ```

   If this checkout already exists, use the update commands below instead of
   cloning over it. An older checkout elsewhere can be left in place while you
   create this checkout; leave `/etc/imunify-discord` untouched.

2. Install from `/opt/imunify-discord`:

   ```bash
   sudo bash install.sh
   ```

   Paste the Discord webhook at the hidden terminal prompt. An existing
   `/etc/imunify-discord/webhook` is reused without prompting. A terminal is
   required only when creating the secret. No webhook argument or environment
   variable is accepted. Use a standard `https://discord.com/api/webhooks/...`
   URL without query parameters (`discordapp.com` is also accepted).

3. Send a harmless delivery test:

   ```bash
   sudo -u _imunify /usr/bin/python3 /etc/imunify-discord/alert.py --test
   ```

   Use your verified notifier identity if different. This sends a test message
   without starting a scan or creating a malware sample. It tests Discord and
   file access; it does not synthesize an ImunifyAV event.

Validate on one staging server first, then repeat these steps on each server.
Each server uses its own system hostname and local configuration. Run the safe
test and confirm the scan path, schedule and intensity on each deployment.

## Configuration and updates

Edit `/etc/imunify-discord/config.env` as root. `config.example.env` documents
the defaults. The file is parsed as data; shell commands, exports, quotes,
unknown keys, and duplicate keys are unsupported.

```ini
SCAN_CRON=0 3 * * *
SCAN_PATH=/home
SCAN_CPU=2
SCAN_IO=2
```

`SCAN_CRON` accepts five numeric cron fields, including lists, ranges and steps.
For weekly scans use `0 3 * * 0`; for every six hours use `0 */6 * * *`.
CPU and I/O intensity range from **1 (lowest) to 7 (highest)**. They apply only
to this project's on-demand scans. The scan directory must already exist.
On DirectAdmin, Hestia and centminmod, confirm that `/home` covers your content;
set `SCAN_PATH` if your deployment stores websites elsewhere.

After editing configuration, or after fetching reviewed project updates:

```bash
cd /opt/imunify-discord
sudo git pull --ff-only
sudo bash update.sh
```

The checkout is root-owned, so use `sudo` for Git updates as shown. Repeat the
update and safe delivery test on each server after validating the change on
staging. After editing only `config.env`, run `sudo bash update.sh` from this
directory to apply the schedule; fetching source updates is optional.

Updates use the same transactional installer, require an existing webhook,
retain `config.env` contents and reuse the secret. Changing the schedule requires
an update to regenerate the single managed cron file. Installation/update does
not send a Discord message automatically. To rotate the webhook, use a root
editor on `/etc/imunify-discord/webhook` and repeat the harmless test; never
paste the secret into a shell command or store it in the checkout.

The managed cron command uses `flock -n` on `/run/imunify-discord-scan.lock`.
ImunifyAV's `on-demand start` is asynchronous: the lock serializes submissions,
not the entire scan lifetime. The agent owns scan execution and busy/queue
handling. Choose a frequency longer than your usual scan duration; this project
does not cancel active scans or modify the built-in background schedule.

## Existing installations

The installer keeps the existing paths `/etc/imunify-discord/alert.py` and
`/etc/imunify-discord/webhook`. It replaces the old script, reuses the webhook,
repairs access permissions, and deduplicates that script's notification entry.

Plain root-crontab entries running `imunify-antivirus malware on-demand start
--path /home` (or `--path=/home`, with an optional `/dev/null` output redirect)
are migrated to the single `/etc/cron.d/imunify-discord` job. Other root cron
entries are preserved. The project's own cron file is replaced atomically.

More complex root-crontab commands or `/home` scans in another `/etc/cron.d`
file cause installation to stop with the file/location identified. Review and
remove the superseded job before rerunning installation. Jobs in other users'
crontabs, systemd timers, or external schedulers need separate administrator
review. Built-in ImunifyAV schedules are intentionally retained.

## Security, delivery and rollback

| Path | Owner/group | Mode |
| --- | --- | --- |
| `/etc/imunify-discord` | root / notifier access group | `0750` |
| `webhook`, `config.env`, `agent` | root / notifier access group | `0640` |
| `alert.py`, `scan.py` | root / notifier access group | `0750` |
| `/etc/cron.d/imunify-discord` | root / root | `0644` |

The webhook never enters command arguments, project logs or notification
registration JSON. The repository ignores live secret/config files and backups;
keep server secrets outside Git. Root and the notifier access group can read
the webhook. Python uses validated Discord HTTPS endpoints, system TLS
verification, a 20-second request timeout, no proxy environment configuration,
and no redirects. Error messages omit URLs, response bodies and raw exceptions.

Before reading existing deployment state, the installer rejects symbolic links,
special files, non-root ownership, and group/other write permissions throughout
the configuration directory and on the managed cron file. Correct ownership and
permissions as root before retrying an installation that fails these checks.
Installed hooks and cron scans use Python isolated mode, ignoring Python
environment overrides and user site packages. Run installation/update only from
a trusted, reviewed checkout; installer Python ignores Python environment overrides
and user site packages while allowing its own local modules.

Alerts deliberately send only the hostname and a generic malware-found message.
File paths, event JSON and file contents are not forwarded to Discord. Inspect
the malware list in ImunifyAV for details. Delivery is one attempt per event;
HTTP errors, rate limits and network failures return nonzero without retries or
a durable queue. Installation does not change existing ImunifyAV/AV+ remediation
policies; review those separately if the server already performs automatic cleanup.

Install/update/uninstall operations are serialized with a separate `flock`.
Before changes, a private rollback directory snapshots the existing configuration,
managed cron and affected notification target. Failures and handled interrupts
restore those files and the target. Rollback failure retains the protected backup
and prints its path for administrator recovery. Successful operations delete the
backup. Concurrent external changes to the same notification target should be
avoided. Power loss or `SIGKILL` cannot trigger Python rollback.

If delivery fails, run the harmless test as the notifier user and check file
permissions, outbound HTTPS/DNS and webhook validity. If manual testing works but
real events fail, check ImunifyAV notifier logs and any SELinux/AppArmor denials;
use an appropriate local policy rather than disabling enforcement. Cron errors
use the server's normal cron output/mail handling; raw agent output is suppressed.

If a first installation fails before the webhook prompt with the generic error
from an older version, fetch the fix and retry installation from the same checkout:

```bash
cd /opt/imunify-discord
sudo git pull --ff-only
sudo bash install.sh
```

The installer opens the terminal for prompt output only; a terminal cannot be
opened as a seekable read/write file. New error messages identify the failing
stage and exception type without printing exception values or webhook secrets.
Use `install.sh` when retrying a failed first installation; `update.sh` requires
an existing webhook. An existing valid webhook is reused without prompting.

## CLI verification

Implementation was checked against the official
[ImunifyAV CLI reference](https://docs.imunify360.com/imunifyav/cli/) on
2026-11-06. The relevant commands are:

```text
imunify-antivirus notifications-config show --json
imunify-antivirus notifications-config update '{"rules":{"CUSTOM_SCAN_MALWARE_FOUND":{"SCRIPT":{"enabled":true,"scripts":["/etc/imunify-discord/alert.py"]}}}}'
imunify-antivirus malware on-demand start --path /home --intensity-cpu 2 --intensity-io 2
```

The JSON above illustrates the API; the installer reads the current target and
merges its script list so other integrations survive. Removal uses the same
`notifications-config update` API with only this script removed, disabling an
empty target. There is no invented `notifications-config add/remove` command.
The ImunifyAV event reference describes `CUSTOM_SCAN_MALWARE_FOUND` as an
on-demand scan completion event with malware found. Built-in background scans
use the `USER_SCAN_*` family and are outside this project's registration.

## Uninstall

```bash
cd /opt/imunify-discord
sudo bash uninstall.sh
```

Removes only this project's notification script entry, managed cron job and
installed Python scripts/agent path. Other hooks survive. Leaves the webhook,
`config.env`, existing unrelated files, ImunifyAV, and its schedules in place.
An active scan is not stopped. Once you no longer need rollback/reinstallation,
you may remove the retained configuration directory yourself.

## Development

```bash
bash -n install.sh update.sh uninstall.sh
python3 -m unittest discover -s tests -v
```

Tests run offline without root, Discord, or ImunifyAV. They cover safe URL
validation, secret redaction, hostname/mention behavior, cron/config validation,
detection-only scan arguments, CLI readback, registration idempotency, legacy
cron migration and rollback. Validate on a staging ImunifyAV server before
rolling out to multiple production servers.
Prompt tests also use a real pseudo-terminal and cover hidden-input failures,
first-install prompting, secret reuse and redacted failure diagnostics.
