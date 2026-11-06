# imunify-discord

ImunifyAV malware notifications for Discord using **Bash + curl + jq**.
No Python interpreter or Python packages are required.
[GitHub repository](https://github.com/juzhax/imunify-discord) · MIT license.

- Enables both `CUSTOM_SCAN_MALWARE_FOUND` and `USER_SCAN_MALWARE_FOUND`.
- Includes hostname, affected users/scan path, supplied malware details and event type.
- Adds a daily 03:00 `/home` on-demand scan with configurable schedule and intensity.
- Preserves other notification hooks, configuration and ImunifyAV's built-in schedule.
- Never requests cleanup, quarantine or deletion of infected files.

## Requirements

Deployment targets: AlmaLinux 9/10 and Ubuntu, including DirectAdmin, Hestia and
centminmod servers with a functioning ImunifyAV CLI. Upstream documents CLI
support for cPanel/DirectAdmin; other panel/OS combinations require validation on
your server. This project does not install ImunifyAV or add unsupported panel support.

Require root, Bash 4+, curl, jq 1.6+, util-linux (`flock`, `runuser`), GNU coreutils
(including `sha256sum`, `stat`), cron/cronie, a trusted CA store, DNS and outbound
HTTPS to Discord. These are distribution packages; no language package manager is used.

```bash
# AlmaLinux
sudo dnf install git curl jq util-linux coreutils cronie ca-certificates
sudo systemctl enable --now crond

# Ubuntu
sudo apt-get update
sudo apt-get install git curl jq util-linux coreutils cron ca-certificates
sudo systemctl enable --now cron
```

## Install

Use `/opt/imunify-discord` for the root-owned checkout and keep configuration in
`/etc/imunify-discord`. Do not clone into the configuration directory. Commands
use `sudo`; omit it when already logged in as root.

1. Clone and inspect the project:

   ```bash
   sudo git clone https://github.com/juzhax/imunify-discord.git /opt/imunify-discord
   cd /opt/imunify-discord
   ```

2. Install:

   ```bash
   sudo bash install.sh
   ```

   An existing `/etc/imunify-discord/webhook` is reused. Otherwise, enter the
   webhook at the hidden terminal prompt. Use an HTTPS Discord webhook without
   query parameters. Never put the webhook in a command argument, Git or logs.

3. Verify both registrations and send safe simulations:

   ```bash
   sudo bash update.sh --verify
   sudo -u _imunify /etc/imunify-discord/alert.sh --test-event both
   ```

   Expect `OK` for both events and two **SIMULATED TEST** Discord messages.
   Simulations neither scan nor change ImunifyAV's detection history.

The notifier normally runs as `_imunify`. The installer uses group `_imunify`
when present, otherwise the notifier user's primary group, and checks real
read/execute/write access as that user. If your notifier uses another identity,
verify it and pass `--notification-user NAME` to install/update; use the same
identity in the test commands. The option does not change ImunifyAV's identity.

Validate on one staging server, then repeat on each server. Hostnames are read
automatically; each deployment keeps its own webhook and configuration.

## Update existing installations

```bash
cd /opt/imunify-discord
sudo git pull --ff-only
sudo bash update.sh
sudo bash update.sh --verify
```

Updates repair both malware events, preserve other hooks, and retain existing
webhook and `config.env` contents. No reinstall or manual ImunifyAV configuration
is needed. Use `install.sh` when retrying an incomplete first installation that
has no saved webhook.

**Migration from the Python version:** the existing registered path
`/etc/imunify-discord/alert.py` is retained as a tiny executable **Bash wrapper**
that calls `alert.sh`. Its extension is only for compatibility; do not run it
through Python. Both events still execute that exact registered path. Existing
cron commands using the known `python3 ... scan.py` invocation are switched to
`/bin/bash /etc/imunify-discord/scan.sh`, retaining their schedule and lock.
The old installed `scan.py` is removed. No Python interpreter is called at runtime.
An unrecognized legacy cron invocation stops the update for administrator review.

## Configuration and scan schedule

Edit `/etc/imunify-discord/config.env` as root:

```ini
SCAN_CRON=0 3 * * *
SCAN_PATH=/home
SCAN_CPU=2
SCAN_IO=2
```

The file is parsed as data, never sourced or evaluated. Define all four keys
without quotes, exports or inline comments. CPU and I/O intensity range from
1 (lowest) to 7 (highest). The scan directory must exist. Scans explicitly use
`--no-follow-symlinks`; confirm `/home` covers your website storage.

The schedule uses the server's local timezone. Five numeric cron fields support
lists, ranges and steps: `0 3 * * 0` is weekly; `0 */6 * * *` is every six hours.
To apply an intentional schedule change:

```bash
cd /opt/imunify-discord
sudo bash update.sh --refresh-cron
```

Ordinary updates retain the cron file, except for the known Python-to-Bash
command migration described above. Path and intensity are read on every scan.
The managed job uses `flock -n`; it serializes submissions, not the asynchronous
scan lifetime. ImunifyAV owns scan execution and busy/queue handling. This project
does not cancel active scans or alter built-in background scan schedules.

## Existing cron jobs

The installer stops if another cron.d file schedules an unmanaged `/home` scan.
For a compatible job, select that file explicitly:

```bash
sudo bash install.sh --migrate-cron /etc/cron.d/imunifyav-nightly
```

Supported form: a root job with `malware on-demand start --path PATH
--no-follow-symlinks --intensity-cpu N --intensity-io N`, in that order, optionally
wrapped in `/usr/bin/flock -n /run/NAME.lock` (or `/var/run`) and followed by
`>> /var/log/NAME.log 2>&1` or `/dev/null` redirection. Schedule, path and intensities
must match the effective configuration. Unsupported/differing commands and
multiple scan entries stop migration without removing the old job.

Only the matching entry is removed. Comments, unrelated entries and old log files
remain; the new job uses normal cron output handling. Migration is repeatable and
rollback restores the selected file if installation fails. Simple legacy root
crontab `/home` scans are also recognized. Review other users' crontabs, systemd
timers and external schedulers separately.

## Missing alerts and safe tests

A working webhook test does not prove either malware event is enabled. Older
versions enabled custom scans only; user-account/background scans need the user event.

1. Repair and verify:

   ```bash
   cd /opt/imunify-discord
   sudo bash update.sh
   sudo bash update.sh --verify
   ```

   Both `CUSTOM_SCAN_MALWARE_FOUND` and `USER_SCAN_MALWARE_FOUND` must report `OK`.
   Verification is read-only and returns nonzero for disabled, missing or duplicate
   project entries. To inspect the agent: `sudo imunify-antivirus notifications-config show --json`.

2. Test safely as the notifier user:

   ```bash
   sudo -u _imunify /etc/imunify-discord/alert.sh --test
   sudo -u _imunify /etc/imunify-discord/alert.sh --test-event both
   ```

   You can substitute either full event name for `both`. Simulations exercise
   formatting/delivery but do not prove that ImunifyAV emitted a real event.
   They bypass duplicate suppression and never create malware or scan history.

3. If tests work but real events do not, inspect the notifier journal:

   ```bash
   sudo journalctl -u imunify-notifier --since '24 hours ago' --no-pager
   ```

   Check permissions, outbound HTTPS, HTTP errors and state warnings. Apply
   appropriate SELinux/AppArmor policy for actual denials without disabling
   enforcement. Review findings in DirectAdmin → ImunifyAV.

Repairs apply to **future events**; past detections are not replayed. Missing
metadata produces a generic alert. Raw stdin is limited to 1 MiB; malformed or
oversized payloads also produce a generic alert. Explicit unrelated events are
ignored. Messages show up to six supplied file records and fit Discord's limit.
No file contents or unrelated raw payload fields are forwarded.

## Security and duplicate suppression

| Path | Owner/group | Mode |
| --- | --- | --- |
| `/etc/imunify-discord` | root / notifier access group | `0750` |
| Webhook, config, agent path, jq filter | root / notifier access group | `0640` |
| Runtime scripts and compatibility wrapper | root / notifier access group | `0750` |
| `/etc/cron.d/imunify-discord` | root / root | `0644` |
| `/var/lib/imunify-discord` | notifier user / primary group | `0700` |
| Private `seen` and lock files | notifier user | `0600` |

`curl` receives the validated webhook through stdin configuration, never arguments.
Its user curlrc and proxy environment are bypassed. HTTPS certificate verification
remains enabled; redirects are not followed. Requests have a 20-second limit;
response bodies and raw curl errors are not logged. Discord mentions are disabled.
Detection metadata includes account/file information: use a restricted channel.

The installer rejects configuration symlinks, special files, non-root ownership
and group/other write access. Configuration is never evaluated as shell code.
Run installation/update from a trusted checkout and trusted administrator shell.

Successful deliveries are recorded as SHA-256 fingerprints plus timestamps in a
private text file, protected by `flock` and atomically replaced. Matching scan/file
identities reported through both event types are suppressed for five minutes.
New files, hashes, signatures, detection IDs or scan identities remain eligible.
If scan identity is missing, identical file identities share the short window.
Overlapping batches with any new finding still generate an alert. State is pruned
on delivery and bounded to 20,000 lines. Large batches (over 200 records) bypass
deduplication rather than risk hiding a distinct finding.

Failures are not cached. Missing identity, unavailable state or lock contention
prefer an extra alert over a lost finding. HTTP ambiguity can still cause a later
repeat: this is best-effort suppression, not exactly-once delivery. There is no
retry queue or automatic retry. Legacy SQLite state from an earlier installation
is unused and may be removed by an administrator; Bash does not access it.

Installation/update/uninstall use a separate lock and private rollback snapshots
for configuration, cron and both notification targets. Handled failures restore
those resources; incomplete rollback retains a protected backup and prints its
location. Avoid concurrent external changes. Power loss or `SIGKILL` cannot run
rollback. Existing ImunifyAV remediation policies are not changed by this project.

## CLI reference

Registration/removal use partial `notifications-config update` operations after
reading `notifications-config show --json`. Both rules have an enabled `SCRIPT`
target containing `/etc/imunify-discord/alert.py`; other scripts survive. Removal
only drops this project's entry and disables an empty target. No native-hook API
or invented add/remove notification commands are used.

Verified against the official [ImunifyAV CLI reference](https://docs.imunify360.com/imunifyav/cli/)
and [reference JSON hook](https://github.com/cloudlinux/imunify360-documentation/blob/master/docs/.vuepress/public/hook_script.py).
The hook reads JSON on stdin, including `event_id`, `scan_id`, `path`,
`malicious_files` and optional totals/timestamps. Common nested wrappers are supported.

## Uninstall and development

```bash
cd /opt/imunify-discord
sudo bash uninstall.sh
```

Removes both project hook entries, runtime scripts and managed cron, preserving
other hooks, configuration, webhook and private state. Active scans are not stopped.

Development checks (no Python):

```bash
bash -n install.sh update.sh uninstall.sh scripts/*.sh tests/*.sh
bash tests/run.sh
sudo bash tests/install-integration.sh
```

Linux CI also runs ShellCheck. Tests use fake curl/ImunifyAV commands and private
fixture directories, never Discord or a real agent. Linux-only integration tests
exercise registration repair, legacy command migration, preservation, rollback
and uninstall as root. Live server/panel validation is still needed before a fleet rollout.
