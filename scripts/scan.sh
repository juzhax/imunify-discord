#!/bin/bash
set +x
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
# shellcheck source=scripts/common.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

# Submits detection-only on-demand scans. Never requests cleanup or quarantine.
scan_main() {
    local agent
    local -a options
    read_config "$CONFIG/config.env" || return 1
    agent=$(< "$CONFIG/agent")
    [[ $agent == /* && -x $agent ]] || { error 'Stored ImunifyAV agent is unavailable.'; return 1; }
    options=(--no-follow-symlinks --intensity-cpu "$SCAN_CPU" --intensity-io "$SCAN_IO")
    # flock in cron serializes submissions; ImunifyAV owns the asynchronous scan.
    if ((${#SCAN_PATHS[@]} == 1)); then
        "$agent" malware on-demand start --path "${SCAN_PATHS[0]}" "${options[@]}" >/dev/null 2>&1 ||
            { error 'Scan submission failed; check agent health and active scans.'; return 1; }
    else
        # ImunifyAV's queue runs the paths one after another.
        "$agent" malware on-demand queue put "${SCAN_PATHS[@]}" "${options[@]}" >/dev/null 2>&1 ||
            { error 'Scan queue submission failed; check agent health and that on-demand queue is supported.'; return 1; }
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then scan_main "$@"; fi
