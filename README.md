# imunify-discord

Minimal Bash + Python integration for ImunifyAV malware alerts in Discord.
Repository: [juzhax/imunify-discord](https://github.com/juzhax/imunify-discord).
MIT licensed; Python standard library only.

- Enables `CUSTOM_SCAN_MALWARE_FOUND` and `USER_SCAN_MALWARE_FOUND`, preserving other hooks and events.
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
| `/var/lib/imunify-discord` | Private notification-user state for duplicate suppression |

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

## Verify and troubleshoot missing malware alerts

A successful `--test` confirms webhook delivery, not notification registration.
Older releases enabled only custom scans. User-account and background scans need
`USER_SCAN_MALWARE_FOUND` as well; enabling only the custom event misses them.

1. Repair the installation and verify both event registrations:

   ```bash
   cd /opt/imunify-discord
   sudo git pull --ff-only
   sudo bash update.sh
   sudo bash update.sh --verify
   ```

   Expect `OK` for both `CUSTOM_SCAN_MALWARE_FOUND` and
   `USER_SCAN_MALWARE_FOUND`. Verification makes no changes and returns nonzero
   if either event is disabled, missing the hook, or lists it more than once.
   The hook must be `/etc/imunify-discord/alert.py` for both events. To inspect
   the agent directly, run `sudo imunify-antivirus notifications-config show --json`.

2. Simulate both event types safely as the notifier user:

   ```bash
   sudo -u _imunify /usr/bin/python3 -I /etc/imunify-discord/alert.py --test-event both
   ```

   Expect two clearly labeled **SIMULATED TEST** messages. You can instead pass
   `CUSTOM_SCAN_MALWARE_FOUND` or `USER_SCAN_MALWARE_FOUND` individually.
   Simulation exercises the message formatting and Discord delivery, bypasses
   duplicate suppression, and neither starts scans nor changes ImunifyAV history.
   It does not prove that the notifier service emitted a real detection event.

3. Check actual event delivery if tests pass but detections still go unreported:

   ```bash
   sudo journalctl -u imunify-notifier --since '24 hours ago' --no-pager
   ```

   Look for disabled hooks, permission errors, HTTP failures or duplicate-cache
   warnings. The notifier must read the webhook, execute the hook and write its
   private state directory. Use the verified notifier identity if it differs from
   `_imunify`. Check SELinux denials and apply an appropriate policy without
   disabling enforcement. Review DirectAdmin → ImunifyAV for the actual findings.

4. Confirm what the test does and does not verify. Repairs apply to future events;
   existing detections are not replayed automatically. An identical detection in
   the same scan can be suppressed for five minutes after successful delivery.
   Distinct findings and new scan identities can generate new alerts. Empty
   fields mean the agent did not supply that detail; no malware sample is needed
   for either safe test option.

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
to this project's on-demand scans. Managed scans explicitly use
`--no-follow-symlinks`. The scan directory must already exist.
On DirectAdmin, Hestia and centminmod, confirm that `/home` covers your content;
set `SCAN_PATH` if your deployment stores websites elsewhere.

To upgrade and repair both malware notification registrations:

```bash
cd /opt/imunify-discord
sudo git pull --ff-only
sudo bash update.sh
```

The checkout is root-owned, so use `sudo` for Git updates as shown. Repeat the
update and safe delivery test on each server after validating the change on
staging. Updates preserve the existing cron file. To deliberately apply a changed
`SCAN_CRON`, run `sudo bash update.sh --refresh-cron` after editing `config.env`.
The scan path and intensity are read from that file at each scheduled submission.

Updates use the same transactional installer, require an existing webhook,
retain `config.env` and existing webhook contents, and repair both event hooks.
An existing daily cron file is preserved unless `--refresh-cron` is requested; a
missing managed cron file is created. Installation/update does
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
repairs access permissions, and registers the script once on both malware-found
events. Running `update.sh` is sufficient; reinstallation is not required.

Plain root-crontab entries running `imunify-antivirus malware on-demand start
--path /home` (or `--path=/home`, with an optional `/dev/null` output redirect)
are migrated to the single `/etc/cron.d/imunify-discord` job. Other root cron
entries are preserved. Installation (or an explicit `--refresh-cron` update)
writes the project's managed cron file atomically; ordinary updates retain it.

More complex root-crontab commands or `/home` scans in another `/etc/cron.d`
file cause installation to stop with the file/location identified. For a
compatible existing cron.d job, select that file explicitly:

```bash
cd /opt/imunify-discord
sudo git pull --ff-only
sudo bash install.sh --migrate-cron /etc/cron.d/imunifyav-nightly
```

This supports a root on-demand command with `--path`, `--no-follow-symlinks`,
`--intensity-cpu` and `--intensity-io` in that order. An optional prefix
`/usr/bin/flock -n /run/NAME.lock` (also `/var/run`) and trailing
`>> /var/log/NAME.log 2>&1` or `/dev/null` redirection are recognized. The schedule,
scan path and both intensities must match the effective `config.env` values
(or the example defaults on first installation). Unsupported commands, differing
settings and multiple scan entries stop migration without removing the old job.

Only the matching entry is removed from the selected file; comments and unrelated
entries remain. The new managed cron file becomes the sole scan schedule for that
entry. The selected file is privately backed up during installation and restored
if installation fails. Repeating the same migration option is safe. Existing log
files are retained; the new job uses normal cron output handling instead of the
old log redirection. Cron checks run before asking for a new webhook.

For other command formats, review and remove only the superseded job before
rerunning installation. Jobs in other users'
crontabs, systemd timers, or external schedulers need separate administrator
review. Built-in ImunifyAV schedules are intentionally retained.

## Security, delivery and rollback

| Path | Owner/group | Mode |
| --- | --- | --- |
| `/etc/imunify-discord` | root / notifier access group | `0750` |
| `webhook`, `config.env`, `agent` | root / notifier access group | `0640` |
| `alert.py`, `scan.py` | root / notifier access group | `0750` |
| `/etc/cron.d/imunify-discord` | root / root | `0644` |
| `/var/lib/imunify-discord` | notifier user / primary group | `0700` |
| `deliveries.sqlite3` and SQLite journal | notifier user | `0600` |

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

Alerts include the server hostname, event type, affected users or scan path,
and file paths/signatures/hashes supplied by ImunifyAV, followed by instructions
to review DirectAdmin → ImunifyAV. Treat the Discord channel as security-sensitive:
it receives account names and detection metadata. File contents, unrelated raw
payload fields, and webhook URLs are not sent. Missing metadata produces a generic
alert instead of a crash; unrelated explicit event types are ignored. Input is
limited to 1 MiB; malformed or oversized input falls back to a generic alert.
Details are bounded to Discord's message limit, with up to six file records shown.
No extra scan or privileged malware-list query is used to enrich messages.

A private SQLite cache suppresses repeat successful deliveries for five minutes.
Fingerprints exclude the event type, so the same scan/detection reported through
both registrations is sent once. Files, users, signatures, hashes and detection
IDs distinguish findings; a new scan ID or timestamp distinguishes a new scan.
When scan identity is absent, identical supplied file identities share the short
five-minute window. Overlapping batches containing any new finding produce an
alert with the scan summary. Cache entries contain only fingerprints and delivery
timestamps, and are expired/pruned during delivery (at most 20,000 entries).

Concurrent hook processes serialize delivery using a SQLite transaction. Only
successful requests enter the cache. If identity or cache access is unavailable,
the hook sends the alert rather than risk discarding a finding. Network ambiguity
(for example, Discord accepts a request but the reply times out) can still cause a
repeat on a later invocation; this is best-effort suppression, not exactly-once
delivery. Simulated events and `--test` never read or modify the live cache.

Delivery is one attempt per invocation; HTTP errors, rate limits and network
failures return nonzero without retries or a durable queue. Installation does
not change existing ImunifyAV/AV+ remediation policies; review those separately
if the server already performs automatic cleanup.

Install/update/uninstall operations are serialized with a separate `flock`.
Before changes, a private rollback directory snapshots the existing configuration,
managed cron and both affected notification targets. Failures and handled interrupts
restore those files and targets. Rollback failure retains the protected backup
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
imunify-antivirus notifications-config update '{"rules":{"CUSTOM_SCAN_MALWARE_FOUND":{"SCRIPT":{"enabled":true,"scripts":["/etc/imunify-discord/alert.py"]}},"USER_SCAN_MALWARE_FOUND":{"SCRIPT":{"enabled":true,"scripts":["/etc/imunify-discord/alert.py"]}}}}'
imunify-antivirus malware on-demand start --path /home --no-follow-symlinks --intensity-cpu 2 --intensity-io 2
```

The JSON above illustrates the API; the installer reads the current target and
merges both script lists so other integrations survive. Removal uses the same
`notifications-config update` API with only this script removed, disabling an
empty target. There is no invented `notifications-config add/remove` command.
The ImunifyAV event reference describes `CUSTOM_SCAN_MALWARE_FOUND` as an
on-demand scan completion event with malware found. Built-in background scans
use `USER_SCAN_MALWARE_FOUND`, which this project also enables. ImunifyAV sends
JSON through stdin using `event_id`, `scan_id`, `path`, `malicious_files` and
optional scan totals/timestamps; see the official
[reference hook](https://github.com/cloudlinux/imunify360-documentation/blob/master/docs/.vuepress/public/hook_script.py).

## Uninstall

```bash
cd /opt/imunify-discord
sudo bash uninstall.sh
```

Removes only this project's script entries from both events, managed cron job and
installed Python scripts/agent path. Other hooks survive. Leaves the webhook,
`config.env`, private duplicate cache, existing unrelated files, ImunifyAV, and
its schedules in place.
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
Event tests cover both registrations and payload types, missing fields, safe
simulations, concurrent duplicate suppression, distinct findings, failed-delivery
retry eligibility, partial-registration rollback, and preservation of existing
webhook contents and cron files during update.
