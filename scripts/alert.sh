#!/bin/bash
set +x
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
ALERT_BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/common.sh
source "$ALERT_BASE/common.sh"
FILTER=$ALERT_BASE/alert.jq

json_event() { jq -c --arg mode "$1" --arg host "$HOST_NAME" --arg simulated "${SIMULATED:-false}" -f "$FILTER" "${2:--}"; }

send_discord() {
    local code
    # -q disables curlrc. The webhook travels through stdin, never argv or logs.
    if ! code=$(printf 'url = "%s"\n' "$WEBHOOK" | curl -q --config - --proto '=https' --noproxy '*' \
        --connect-timeout 10 --max-time 20 --silent --output "$WORK/response" --write-out '%{http_code}' \
        --request POST --header 'Content-Type: application/json' --data-binary "@$WORK/message" 2>/dev/null); then
        error 'Discord request failed; check DNS and HTTPS access.'; return 1
    fi
    [[ $code == 200 || $code == 204 ]] || { error "Discord rejected the notification (HTTP ${code//[^0-9]/}). Check webhook validity or rate limits."; return 1; }
}

cache_open() {
    local path owner mode links
    [[ -d $STATE && ! -L $STATE ]] || return 1
    read -r owner mode < <(stat -c '%u %a' -- "$STATE")
    [[ $owner == "$UID" ]] && (( (8#$mode & 8#077) == 0 )) || return 1
    for path in "$STATE/.lock" "$STATE/seen"; do
        [[ ! -L $path ]] || return 1
        if [[ -e $path ]]; then
            [[ -f $path ]] || return 1
            read -r owner mode links < <(stat -c '%u %a %h' -- "$path")
            [[ $owner == "$UID" && $links == 1 ]] && (( (8#$mode & 8#077) == 0 )) || return 1
        fi
    done
    { exec 9>>"$STATE/.lock"; } 2>/dev/null || return 1
    flock -x -w 25 9 || return 1
    chmod 600 "$STATE/.lock" || return 1
    CACHE_TIME=$(date +%s)
    if [[ -f $STATE/seen ]]; then
        awk -v now="$CACHE_TIME" '$1 ~ /^[0-9]+$/ && length($2)==64 && $2 !~ /[^0-9a-f]/ && $1>now-300 && $1<=now+60 {print $1" "$2}' "$STATE/seen" > "$WORK/seen" || return 1
    else : > "$WORK/seen"; fi
}

alert_main() {
    local test_mode='' event_type key duplicate cache=false
    local -a keys=()
    case ${1:-} in
        '') (($#==0)) || return 1;;
        --test) (($#==1)) || return 1; test_mode=delivery;;
        --test-event) (($#==2)) || { error '--test-event requires an event name or both.'; return 1; }
            case $2 in "$EVENT_CUSTOM"|"$EVENT_USER"|both) test_mode=$2;; *) error 'Unsupported test event.'; return 1;; esac;;
        -h|--help) printf 'Usage: alert.sh [--test | --test-event CUSTOM_SCAN_MALWARE_FOUND|USER_SCAN_MALWARE_FOUND|both]\n'; return 0;;
        *) error 'Unknown option.'; return 1;;
    esac
    for key in curl jq flock sha256sum stat; do need "$key" || return 1; done
    umask 077
    WORK=$(mktemp -d) || return 1
    CACHE_TMP=
    trap 'rm -rf -- "$WORK"; [[ -z ${CACHE_TMP:-} ]] || rm -f -- "$CACHE_TMP"' EXIT
    WEBHOOK=$(< "$CONFIG/webhook")
    valid_webhook "$WEBHOOK" || { error 'Invalid webhook format.'; return 1; }
    HOST_NAME=$(hostname)
    if [[ $test_mode == delivery ]]; then
        jq -n --arg host "$HOST_NAME" '{username:($host[0:80]),content:"ImunifyAV Discord test: notification delivery is working. No scan was started.",allowed_mentions:{parse:[]}}' > "$WORK/message"
        send_discord || return 1
        printf 'Discord test sent.\n'; return 0
    fi
    if [[ -n $test_mode ]]; then
        SIMULATED=true
        for event_type in "$EVENT_CUSTOM" "$EVENT_USER"; do
            [[ $test_mode == both || $test_mode == "$event_type" ]] || continue
            jq -n --arg e "$event_type" '{event_id:$e,user:"example-user",path:"/home/example-user",malicious_files:[{path:"/home/example-user/public_html/example.php",signature:"SIMULATED-DETECTION-NOT-MALWARE"}]}' |
                json_event normalize > "$WORK/event"
            json_event payload "$WORK/event" > "$WORK/message"
            send_discord || return 1
        done
        printf 'Simulated Discord event notification(s) sent.\n'; return 0
    fi
    # Bounded stdin: no event JSON is echoed or logged.
    head -c 1048577 > "$WORK/input"
    if [[ $(wc -c < "$WORK/input") -gt 1048576 ]] || ! json_event normalize "$WORK/input" > "$WORK/event" 2>/dev/null ||
       ! jq -se 'length==1' "$WORK/event" >/dev/null 2>&1; then
        printf '{}\n' | json_event normalize > "$WORK/event"
    fi
    event_type=$(jq -r .event_type "$WORK/event")
    case $event_type in "$EVENT_CUSTOM"|"$EVENT_USER"|UNKNOWN_MALWARE_EVENT) ;; *) return 0;; esac
    while IFS= read -r key; do keys+=("$key"); done < <(
        json_event keys "$WORK/event" | while IFS= read -r identity; do printf '%s' "$identity" | sha256sum | cut -d ' ' -f 1; done)
    if ((${#keys[@]})); then
        if cache_open; then
            cache=true; duplicate=true
            for key in "${keys[@]}"; do grep -Fq -- " $key" "$WORK/seen" || duplicate=false; done
            [[ $duplicate == false ]] || return 0
        else printf 'Warning: duplicate state unavailable; sending without suppression.\n' >&2; fi
    fi
    json_event payload "$WORK/event" > "$WORK/message"
    send_discord || return 1
    if [[ $cache == true ]]; then
        # Commit only after Discord accepts the message. The separate lock inode
        # stays stable while the private cache file is replaced atomically.
        if CACHE_TMP=$(mktemp "$STATE/.seen.XXXXXX") &&
           { cat "$WORK/seen"; for key in "${keys[@]}"; do printf '%s %s\n' "$CACHE_TIME" "$key"; done; } | tail -n 20000 > "$CACHE_TMP" &&
           mv -f -- "$CACHE_TMP" "$STATE/seen"; then CACHE_TMP=
        else printf 'Warning: delivery succeeded but duplicate state could not be saved.\n' >&2; fi
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then alert_main "$@"; fi
