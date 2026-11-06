#!/bin/bash
set +x
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
command -v python3 >/dev/null || { echo 'Error: install Python 3 first.' >&2; exit 1; }
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
exec python3 -E -s scripts/manage.py install "$@"
