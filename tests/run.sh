#!/bin/bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/scripts/common.sh"
TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEST_DIR"' EXIT
COUNT=0
pass() { COUNT=$((COUNT+1)); printf 'ok %s - %s\n' "$COUNT" "$1"; }
assert_json() { jq -e "$2" <<< "$1" >/dev/null || { printf 'FAIL: %s\n' "$3" >&2; exit 1; }; pass "$3"; }
normalize() { jq -c --arg mode normalize --arg host host.example.invalid --arg simulated false -f "$ROOT/scripts/alert.jq"; }
format() { jq -c --arg mode payload --arg host host.example.invalid --arg simulated false -f "$ROOT/scripts/alert.jq"; }
keys() { jq -c --arg mode keys --arg host host.example.invalid --arg simulated false -f "$ROOT/scripts/alert.jq"; }

for e in "$EVENT_CUSTOM" "$EVENT_USER"; do
    raw=$(jq -nc --arg e "$e" '{event_id:$e,scan_id:"example-scan",path:"/home/example-user",malicious_files:["/home/example-user/bad.php"]}')
    normalized=$(normalize <<< "$raw")
    assert_json "$normalized" '.user=="example-user" and .records[0].path=="/home/example-user/bad.php"' "parse $e"
    assert_json "$(format <<< "$normalized")" '.content|contains("DirectAdmin → ImunifyAV") and contains("example-user")' "format $e"
done
CUSTOM=$(jq -nc --arg e "$EVENT_CUSTOM" '{event_id:$e,scan_id:"example-scan",path:"/home/example-user",malicious_files:["/home/example-user/bad.php"]}')
USER=$(jq -c --arg e "$EVENT_USER" '.event_id=$e' <<< "$CUSTOM")
[[ $(normalize <<< "$CUSTOM" | keys) == "$(normalize <<< "$USER" | keys)" ]]; pass 'fingerprints ignore event type'
for raw in '{}' 'null' '[]' '123' '{"data":{"user":null,"path":[],"malicious_files":[null,42,{}]}}'; do
    assert_json "$(normalize <<< "$raw" | format)" '.content|contains("DirectAdmin")' 'missing fields do not crash'
done
raw='{"event":{"name":"USER_SCAN_MALWARE_FOUND"},"data":{"params":{"user":{"name":"example-user"},"scan_path":"/srv/sites","detections":[{"filename":"/srv/sites/bad.php","type":"EXAMPLE-SIGNATURE","sha256":"abc"}]}}}'
assert_json "$(normalize <<< "$raw")" '.event_type=="USER_SCAN_MALWARE_FOUND" and .user=="example-user" and .records[0].signature=="EXAMPLE-SIGNATURE"' 'wrapped payload and file details'
raw='{"malicious_files":{"example-user":["/home/example-user/a.php"],"another-user":["/home/another-user/b.php"]}}'
assert_json "$(normalize <<< "$raw")" '([.records[].user]|unique|length)==2' 'multiple affected users'
raw='{"event_id":"identifier","type":"USER_SCAN_MALWARE_FOUND","file_path":"/home/example-user/a.php"}'
assert_json "$(normalize <<< "$raw")" '.event_type=="USER_SCAN_MALWARE_FOUND" and .records[0].signature==""' 'scan type is not a malware signature'
raw='{"malicious_files":[{"path":"/home/example-user/a.php","signature":"https://discord.com/api/webhooks/123/synthetic_test_value @everyone\n"}]}'
assert_json "$(normalize <<< "$raw" | format)" '(.content|contains("synthetic_test_value")|not) and (.content|contains("@everyone")|not) and .allowed_mentions.parse==[]' 'redact secrets and disable mentions'
raw=$(jq -nc '{malicious_files:[range(0;201)|("/home/example-user/"+tostring)]}')
[[ -z $(normalize <<< "$raw" | keys) ]]; pass 'oversized detection batches fail open for dedup'
for schedule in '0 3 * * *' '*/30 1-4 * * 0,6' '0 */6 * * *'; do validate_cron "$schedule"; done
pass 'valid cron ranges, lists and steps'
for schedule in '60 3 * * *' '* 24 * * *' '* * 0 * *' '@daily' '* * * * */0' '* * * * 7-1' '* * * * *;id'; do
    if validate_cron "$schedule" 2>/dev/null; then printf 'FAIL: unsafe cron accepted\n'; exit 1; fi
done
pass 'invalid cron values rejected'
printf 'SCAN_CRON=0 3 * * *\nSCAN_PATH=%s\nSCAN_CPU=2\nSCAN_IO=2\n' "$TEST_DIR" > "$TEST_DIR/config.env"
read_config "$TEST_DIR/config.env"; pass 'configuration parsed as data'
mkdir -p "$TEST_DIR/volumes" "$TEST_DIR/home"
parse_scan_paths "$TEST_DIR/home  $TEST_DIR/volumes"
[[ ${#SCAN_PATHS[@]} == 2 && ${SCAN_PATHS[1]} == "$TEST_DIR/volumes" ]]; pass 'multiple scan paths parsed'
for bad in "$TEST_DIR/home $TEST_DIR/home" "$TEST_DIR/vol*" 'relative/path' "$TEST_DIR/missing" ''; do
    if parse_scan_paths "$bad" 2>/dev/null; then printf 'FAIL: bad scan path accepted: %s\n' "$bad"; exit 1; fi
done
pass 'duplicate, wildcard, relative, missing and empty scan paths rejected'

mkdir "$TEST_DIR/scan"
printf '%s\n' "$TEST_DIR/fake-agent" > "$TEST_DIR/scan/agent"
printf '#!/bin/bash\nprintf "%%s\\n" "$*" >> "%s"\n' "$TEST_DIR/agent-calls" > "$TEST_DIR/fake-agent"
chmod +x "$TEST_DIR/fake-agent"
run_scan() {
    printf 'SCAN_CRON=0 3 * * *\nSCAN_PATH=%s\nSCAN_CPU=2\nSCAN_IO=3\n' "$1" > "$TEST_DIR/scan/config.env"
    rm -f "$TEST_DIR/agent-calls"
    "$BASH" -c 'source "$1/scripts/scan.sh"; CONFIG=$2; scan_main' test "$ROOT" "$TEST_DIR/scan"
}
run_scan "$TEST_DIR/home"
[[ $(< "$TEST_DIR/agent-calls") == "malware on-demand start --path $TEST_DIR/home --no-follow-symlinks --intensity-cpu 2 --intensity-io 3" ]]
pass 'single path uses on-demand start'
run_scan "$TEST_DIR/home $TEST_DIR/volumes"
[[ $(< "$TEST_DIR/agent-calls") == "malware on-demand queue put $TEST_DIR/home $TEST_DIR/volumes --no-follow-symlinks --intensity-cpu 2 --intensity-io 3" ]]
pass 'multiple paths use one on-demand queue submission'
! grep -Eq 'cleanup|quarantine|restore|remove' "$TEST_DIR/agent-calls"; pass 'scan never requests remediation'

printf 'EVIL=$(touch /tmp/never-run)\n' >> "$TEST_DIR/config.env"
if read_config "$TEST_DIR/config.env" 2>/dev/null; then exit 1; fi
pass 'unknown configuration cannot execute shell code'

mkdir "$TEST_DIR/bin" "$TEST_DIR/config" "$TEST_DIR/state"
chmod 700 "$TEST_DIR/state"
printf 'https://discord.com/api/webhooks/123/synthetic_test_value\n' > "$TEST_DIR/config/webhook"
export TEST_TRACE=$TEST_DIR/trace TEST_ARGS=$TEST_DIR/args TEST_CURL_CONFIG=$TEST_DIR/curl-config
cat > "$TEST_DIR/bin/hostname" <<'MOCK'
#!/bin/bash
printf 'host.example.invalid\n'
MOCK
cat > "$TEST_DIR/bin/curl" <<'MOCK'
#!/bin/bash
set -e
cat > "$TEST_CURL_CONFIG"
printf '%s\n' "$@" >> "$TEST_ARGS"
while (($#)); do
    if [[ $1 == --data-binary ]]; then shift; cat "${1#@}" >> "$TEST_TRACE"; fi
    shift
done
if [[ ${TEST_CURL_FAIL:-false} == true ]]; then printf 'private-value-must-not-leak\n' >&2; exit 28; fi
printf '%s' "${TEST_CURL_CODE:-204}"
MOCK
chmod +x "$TEST_DIR/bin/hostname" "$TEST_DIR/bin/curl"
run_alert() {
    /bin/bash -c 'source "$1/scripts/alert.sh"; CONFIG=$2; STATE=$3; PATH="$4:$PATH"; shift 4; alert_main "$@"' \
        test "$ROOT" "$TEST_DIR/config" "$TEST_DIR/state" "$TEST_DIR/bin" "$@"
}
clear_alerts() { rm -f "$TEST_DIR/state/seen" "$TEST_TRACE" "$TEST_ARGS"; }
if command -v flock >/dev/null && [[ $(uname -s) == Linux ]]; then
    run_alert --test-event both >/dev/null
    [[ $(wc -l < "$TEST_TRACE") -eq 2 ]]; pass 'both event simulations send without live cache'
    [[ ! -f $TEST_DIR/state/seen ]]; pass 'simulations do not write dedup state'
    ! grep -Fq synthetic_test_value "$TEST_ARGS"; pass 'webhook never appears in curl arguments'
    grep -Fq synthetic_test_value "$TEST_CURL_CONFIG"; pass 'curl receives webhook through stdin'
    clear_alerts
    run_alert <<< "$CUSTOM"
    run_alert <<< "$USER"
    [[ $(wc -l < "$TEST_TRACE") -eq 1 ]]; pass 'both event types suppress identical findings'
    distinct=$(jq -c '.malicious_files += ["/home/another-user/new.php"]' <<< "$USER")
    run_alert <<< "$distinct"
    [[ $(wc -l < "$TEST_TRACE") -eq 2 ]]; pass 'overlapping batch with distinct infection still alerts'
    new_scan=$(jq -c '.scan_id="another-scan"' <<< "$CUSTOM")
    run_alert <<< "$new_scan"
    [[ $(wc -l < "$TEST_TRACE") -eq 3 ]]; pass 'new scans generate alerts'
    ! grep -Eq 'example-user|bad.php|synthetic_test_value' "$TEST_DIR/state/seen"; pass 'state contains only hashes and timestamps'
    clear_alerts
    run_alert <<< "$CUSTOM" & p1=$!
    run_alert <<< "$USER" & p2=$!
    wait "$p1"; wait "$p2"
    [[ $(wc -l < "$TEST_TRACE") -eq 1 ]]; pass 'concurrent events send once'
    clear_alerts
    export TEST_CURL_FAIL=true
    if run_alert <<< "$CUSTOM" > "$TEST_DIR/out" 2> "$TEST_DIR/err"; then exit 1; fi
    ! grep -q private-value "$TEST_DIR/err"; pass 'network failures do not expose curl error values'
    [[ ! -s $TEST_DIR/state/seen ]]; pass 'failed delivery is not recorded'
    unset TEST_CURL_FAIL
    run_alert <<< "$CUSTOM"
    [[ $(wc -l < "$TEST_TRACE") -eq 2 ]]; pass 'failed delivery stays eligible for retry'
    clear_alerts
    run_alert <<< '{broken'
    [[ $(wc -l < "$TEST_TRACE") -eq 1 ]]; pass 'malformed JSON produces a generic alert'
    clear_alerts
    run_alert <<< '{"event_id":"USER_SCAN_FINISHED"}'
    [[ ! -e $TEST_TRACE ]]; pass 'unrelated events are ignored'
else printf 'SKIP Linux transport/flock tests on this development host; exercised in Linux CI.\n'; fi
printf '%s tests passed.\n' "$COUNT"
