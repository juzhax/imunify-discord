#!/bin/bash
set +x
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
# shellcheck source=scripts/common.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
read_config "$CONFIG/config.env"
AGENT=$(< "$CONFIG/agent")
[[ $AGENT == /* && -x $AGENT ]] || { error 'Stored ImunifyAV agent is unavailable.'; exit 1; }
# flock in cron serializes submissions; ImunifyAV owns the asynchronous scan.
if ! "$AGENT" malware on-demand start --path "$SCAN_PATH" --no-follow-symlinks \
    --intensity-cpu "$SCAN_CPU" --intensity-io "$SCAN_IO" >/dev/null 2>&1; then
    error 'Scan submission failed; check agent health and active scans.'; exit 1
fi
