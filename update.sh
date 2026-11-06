#!/bin/bash
set +x
set -euo pipefail
# Repair both malware events; preserve cron unless --refresh-cron is explicit.
# --verify checks the registrations without changing deployment state.
exec /bin/bash "$(dirname -- "${BASH_SOURCE[0]}")/install.sh" --update "$@"
