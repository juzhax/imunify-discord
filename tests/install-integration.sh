#!/bin/bash
# Linux-only root integration tests. All deployment paths and the CLI are fixtures.
set -euo pipefail
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ $(uname -s) == Linux && $EUID == 0 ]] || { printf 'SKIP root/Linux installation integration tests.\n'; exit 0; }
TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEST_DIR"' EXIT
mkdir "$TEST_DIR/bin" "$TEST_DIR/config" "$TEST_DIR/cron.d" "$TEST_DIR/run"
export TEST_AGENT_STATE=$TEST_DIR/agent-state TEST_CRONTAB=$TEST_DIR/root-crontab
jq -n '{items:{rules:{CUSTOM_SCAN_MALWARE_FOUND:{SCRIPT:{enabled:true,scripts:["/etc/imunify-discord/alert.py","/opt/existing-hook"]}},USER_SCAN_MALWARE_FOUND:{SCRIPT:{enabled:false,scripts:[]}},UNRELATED:{SCRIPT:{enabled:true,scripts:["/opt/another-hook"]}}}}}' > "$TEST_AGENT_STATE"
printf '# existing job\n0 1 * * * /usr/bin/backup\n' > "$TEST_CRONTAB"
printf 'https://discord.com/api/webhooks/123/synthetic_test_value' > "$TEST_DIR/config/webhook"
printf 'SCAN_CRON=0 3 * * *\nSCAN_PATH=/home\nSCAN_CPU=2\nSCAN_IO=2\n' > "$TEST_DIR/config/config.env"
chmod 640 "$TEST_DIR/config/"*
printf '# preserve this schedule\n0 3 * * * root /usr/bin/flock -n /run/imunify-discord-scan.lock /usr/bin/python3 -I /etc/imunify-discord/scan.py\n' > "$TEST_DIR/cron.d/imunify-discord"
cp "$TEST_DIR/config/webhook" "$TEST_DIR/webhook-before"
cp "$TEST_DIR/config/config.env" "$TEST_DIR/config-before"
cat > "$TEST_DIR/bin/imunify-antivirus" <<'MOCK'
#!/bin/bash
set -euo pipefail
if [[ $* == *--help* ]]; then printf '%s\n' '--path --no-follow-symlinks --intensity-cpu --intensity-io'; exit 0; fi
if [[ $1 == notifications-config && $2 == show ]]; then cat "$TEST_AGENT_STATE"; exit 0; fi
if [[ $1 == notifications-config && $2 == update ]]; then
    jq --argjson patch "$3" '.items *= $patch' "$TEST_AGENT_STATE" > "$TEST_AGENT_STATE.new"
    if [[ -n ${TEST_PARTIAL_FAIL:-} && ! -f $TEST_PARTIAL_FAIL ]]; then
        touch "$TEST_PARTIAL_FAIL"
        jq '.items.rules.USER_SCAN_MALWARE_FOUND.SCRIPT.enabled=false' "$TEST_AGENT_STATE.new" > "$TEST_AGENT_STATE.partial"
        mv "$TEST_AGENT_STATE.partial" "$TEST_AGENT_STATE.new"
    fi
    mv "$TEST_AGENT_STATE.new" "$TEST_AGENT_STATE"
    cat "$TEST_AGENT_STATE"; exit 0
fi
exit 1
MOCK
cat > "$TEST_DIR/bin/crontab" <<'MOCK'
#!/bin/bash
if [[ $1 == -l ]]; then cat "$TEST_CRONTAB"; else cp "$1" "$TEST_CRONTAB"; fi
MOCK
cat > "$TEST_DIR/bin/systemctl" <<'MOCK'
#!/bin/bash
exit 0
MOCK
chmod +x "$TEST_DIR/bin/"*
run_manager() {
    /bin/bash -c 'source "$1/scripts/manage.sh"; CONFIG=$2/config; CRON_DIR=$2/cron.d; CRON=$CRON_DIR/imunify-discord; STATE=$2/state; RUN_DIR=$2/run; PATH="$2/bin:$PATH"; shift 2; manager_main "$@"' test "$REPO" "$TEST_DIR" "$@"
}
run_manager install --update --notification-user root
run_manager install --verify
cmp "$TEST_DIR/webhook-before" "$TEST_DIR/config/webhook"
cmp "$TEST_DIR/config-before" "$TEST_DIR/config/config.env"
grep -Fq '0 3 * * * root /usr/bin/flock -n /run/imunify-discord-scan.lock /bin/bash /etc/imunify-discord/scan.sh' "$TEST_DIR/cron.d/imunify-discord"
grep -Fq '# preserve this schedule' "$TEST_DIR/cron.d/imunify-discord"
grep -Fq '#!/bin/bash' "$TEST_DIR/config/alert.py"
[[ ! -f $TEST_DIR/config/scan.py ]]
jq -e '.items.rules.UNRELATED.SCRIPT.scripts==["/opt/another-hook"] and (.items.rules.CUSTOM_SCAN_MALWARE_FOUND.SCRIPT.scripts|index("/opt/existing-hook"))!=null' "$TEST_AGENT_STATE" >/dev/null
printf 'ok - update repairs both events, migrates Python invocation and preserves configuration/other hooks\n'
cp "$TEST_DIR/cron.d/imunify-discord" "$TEST_DIR/cron-before"
run_manager install --update --notification-user root
cmp "$TEST_DIR/cron-before" "$TEST_DIR/cron.d/imunify-discord"
printf 'ok - repeated update is idempotent\n'

# Exact supported legacy job, with comments and an unrelated entry.
cat > "$TEST_DIR/cron.d/legacy-nightly" <<'CRON'
# retain this comment
0 1 * * * root /usr/bin/backup
0 3 * * * root /usr/bin/flock -n /run/legacy-nightly.lock /usr/bin/imunify-antivirus malware on-demand start --path /home --no-follow-symlinks --intensity-cpu 2 --intensity-io 2 >> /var/log/legacy-nightly.log 2>&1
CRON
run_manager install --update --notification-user root --migrate-cron "$TEST_DIR/cron.d/legacy-nightly"
grep -Fq '# retain this comment' "$TEST_DIR/cron.d/legacy-nightly"
grep -Fq '/usr/bin/backup' "$TEST_DIR/cron.d/legacy-nightly"
! grep -q on-demand "$TEST_DIR/cron.d/legacy-nightly"
printf 'ok - explicit legacy migration preserves unrelated entries\n'

# Force a partial registration failure and verify the transaction restores both.
jq '.items.rules.USER_SCAN_MALWARE_FOUND.SCRIPT.enabled=false' "$TEST_AGENT_STATE" > "$TEST_DIR/before-failure"
cp "$TEST_DIR/before-failure" "$TEST_AGENT_STATE"
export TEST_PARTIAL_FAIL=$TEST_DIR/partial-failure-marker
if run_manager install --update --notification-user root > "$TEST_DIR/failure-out" 2> "$TEST_DIR/failure-err"; then printf 'FAIL: partial update accepted\n'; exit 1; fi
jq -S . "$TEST_DIR/before-failure" > "$TEST_DIR/expected"
jq -S . "$TEST_AGENT_STATE" > "$TEST_DIR/actual"
cmp "$TEST_DIR/expected" "$TEST_DIR/actual"
cmp "$TEST_DIR/webhook-before" "$TEST_DIR/config/webhook"
cmp "$TEST_DIR/cron-before" "$TEST_DIR/cron.d/imunify-discord"
printf 'ok - failed update restores both event registrations and original files\n'
unset TEST_PARTIAL_FAIL
run_manager install --update --notification-user root
run_manager uninstall
[[ -f $TEST_DIR/config/webhook && -f $TEST_DIR/config/config.env && ! -f $TEST_DIR/config/alert.sh ]]
jq -e 'all(.items.rules.CUSTOM_SCAN_MALWARE_FOUND.SCRIPT.scripts[], .items.rules.USER_SCAN_MALWARE_FOUND.SCRIPT.scripts[]; .!="/etc/imunify-discord/alert.py") and .items.rules.CUSTOM_SCAN_MALWARE_FOUND.SCRIPT.enabled==true' "$TEST_AGENT_STATE" >/dev/null
printf 'ok - uninstall removes both project hooks and preserves others and configuration\n'
