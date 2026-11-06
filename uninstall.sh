#!/bin/bash
set +x
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
exec python3 -E -s scripts/manage.py uninstall "$@"
