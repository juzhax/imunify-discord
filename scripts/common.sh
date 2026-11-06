#!/bin/bash
# Shared Linux helpers. Configuration is parsed as data, never sourced/evaluated.
# These globals are consumed by the scripts sourcing this library.
# shellcheck disable=SC2034
EVENT_CUSTOM=CUSTOM_SCAN_MALWARE_FOUND
EVENT_USER=USER_SCAN_MALWARE_FOUND
HOOK=/etc/imunify-discord/alert.py
CONFIG=/etc/imunify-discord
STATE=/var/lib/imunify-discord
CRON_DIR=/etc/cron.d
CRON=/etc/cron.d/imunify-discord
RUN_DIR=/run

error() { printf 'Error: %s\n' "$*" >&2; return 1; }
need() { command -v "$1" >/dev/null || error "Missing dependency: $1"; }

validate_cron() {
    local schedule=$1 field term base step n i=0
    local -a fields terms bounds lows=(0 0 1 1 0) highs=(59 23 31 12 7)
    read -r -a fields <<< "$schedule"
    ((${#fields[@]} == 5)) || { error 'SCAN_CRON requires five numeric cron fields.'; return 1; }
    for field in "${fields[@]}"; do
        [[ $field =~ ^[0-9*/,\-]+$ && $field != *, && $field != ,* && $field != *,,* ]] || return 1
        IFS=, read -r -a terms <<< "$field"
        for term in "${terms[@]}"; do
            base=${term%%/*}
            if [[ $term == */* ]]; then
                step=${term#*/}
                [[ $step =~ ^[0-9]{1,2}$ ]] && ((10#$step >= 1 && 10#$step <= highs[i]+1)) || return 1
            fi
            if [[ $base != '*' ]]; then
                [[ $base =~ ^[0-9]{1,2}(-[0-9]{1,2})?$ ]] || return 1
                IFS=- read -r -a bounds <<< "$base"
                for n in "${bounds[@]}"; do ((10#$n >= lows[i] && 10#$n <= highs[i])) || return 1; done
                ((${#bounds[@]} < 2)) || ((10#${bounds[0]} <= 10#${bounds[1]})) || return 1
            fi
        done
        i=$((i+1))
    done
}

# SCAN_PATH holds one or more space-separated directories, e.g. "/home /var/lib/docker/volumes".
# Results go to the SCAN_PATHS array. Wildcards are rejected because ImunifyAV expands them itself.
parse_scan_paths() {
    local path
    local -A unique=()
    SCAN_PATHS=()
    read -r -a SCAN_PATHS <<< "$1"
    ((${#SCAN_PATHS[@]} >= 1 && ${#SCAN_PATHS[@]} <= 16)) || { error 'SCAN_PATH needs 1 to 16 space-separated directories.'; return 1; }
    for path in "${SCAN_PATHS[@]}"; do
        [[ $path == /* && $path != *[*?[]* && -d $path ]] || { error "SCAN_PATH entry must be an existing absolute directory without wildcards: $path"; return 1; }
        [[ ! ${unique[$path]+yes} ]] || { error "Duplicate SCAN_PATH entry: $path"; return 1; }
        unique[$path]=1
    done
}

read_config() {
    local file=$1 line key value
    local -A seen=()
    SCAN_CRON='' SCAN_PATH='' SCAN_CPU='' SCAN_IO=''
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
        [[ $line == *=* ]] || { error 'Invalid configuration line.'; return 1; }
        key=${line%%=*}; value=${line#*=}
        [[ $key =~ ^SCAN_(CRON|PATH|CPU|IO)$ ]] || { error 'Unknown configuration key.'; return 1; }
        [[ ! ${seen[$key]+yes} ]] || { error 'Duplicate configuration key.'; return 1; }
        case $key in
            SCAN_CRON) SCAN_CRON=$value;; SCAN_PATH) SCAN_PATH=$value;;
            SCAN_CPU) SCAN_CPU=$value;; SCAN_IO) SCAN_IO=$value;;
            *) error 'Unknown configuration key.'; return 1;;
        esac
        seen[$key]=1
    done < "$file"
    ((${#seen[@]} == 4)) || { error 'Define all four scan configuration keys.'; return 1; }
    [[ $SCAN_CPU =~ ^[1-7]$ && $SCAN_IO =~ ^[1-7]$ ]] || { error 'Scan intensity must be 1 through 7.'; return 1; }
    parse_scan_paths "$SCAN_PATH" || return 1
    validate_cron "$SCAN_CRON" || { error 'Invalid SCAN_CRON schedule.'; return 1; }
}

valid_webhook() {
    [[ $1 =~ ^https://(discord\.com|discordapp\.com)/api/webhooks/[0-9]+/[A-Za-z0-9_-]+$ ]]
}

trusted_path() {
    local path=$1 mode owner
    [[ ! -L $path ]] || { error "Refusing symbolic link: $path"; return 1; }
    [[ -e $path ]] || return 0
    [[ -f $path || -d $path ]] || { error "Not a regular file/directory: $path"; return 1; }
    read -r owner mode < <(stat -c '%u %a' -- "$path")
    if [[ $owner != 0 ]] || (( (8#$mode & 8#022) != 0 )); then
        error "Require root ownership and no group/other writes: $path"; return 1
    fi
}

notification_show() {
    local raw
    raw=$("$AGENT" notifications-config show --json 2>/dev/null) || { error 'Unable to read ImunifyAV notifications-config.'; return 1; }
    jq -ce --arg c "$EVENT_CUSTOM" --arg u "$EVENT_USER" '
      (.items // .).rules | if type != "object" then error("schema") else . end |
      {($c): (.[$c].SCRIPT // {enabled:false,scripts:[]}), ($u): (.[$u].SCRIPT // {enabled:false,scripts:[]})} |
      with_entries(.value |= {enabled:.enabled,scripts:.scripts}) |
      if all(.[]; (.enabled|type)=="boolean" and (.scripts|type)=="array" and all(.scripts[]; type=="string" and startswith("/")))
      then . else error("schema") end' <<< "$raw" 2>/dev/null || { error 'Unsupported notification configuration schema.'; return 1; }
}

notification_desired() {
    local remove=$1
    jq -c --arg hook "$HOOK" --argjson remove "$remove" '
      with_entries(.value |= (
        if $remove and (.scripts|index($hook)|not) then . else
          .scripts |= map(select(. != $hook)) |
          if $remove then (if (.scripts|length)==0 then .enabled=false else . end)
          else .scripts += [$hook] | .enabled=true end
        end))'
}

notification_apply() {
    local targets=$1 patch actual
    patch=$(jq -c '{rules: with_entries(.value = {SCRIPT: .value})}' <<< "$targets") || return 1
    "$AGENT" notifications-config update "$patch" >/dev/null 2>&1 || { error 'ImunifyAV rejected notification registration.'; return 1; }
    actual=$(notification_show) || return 1
    [[ $(jq -cS . <<< "$actual") == "$(jq -cS . <<< "$targets")" ]] || { error 'Notification registration readback failed.'; return 1; }
}

notification_verify() {
    local targets event ok=0
    targets=$(notification_show) || return 1
    for event in "$EVENT_CUSTOM" "$EVENT_USER"; do
        if jq -e --arg e "$event" --arg h "$HOOK" '.[$e].enabled and ([.[$e].scripts[]|select(.==$h)]|length)==1' <<< "$targets" >/dev/null; then
            printf '%s: OK (enabled; hook registered once)\n' "$event"
        else printf '%s: FAIL (disabled, missing or duplicate hook)\n' "$event"; ok=1; fi
    done
    return "$ok"
}
