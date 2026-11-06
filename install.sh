#!/bin/bash
set +x
set -euo pipefail
exec /bin/bash "$(dirname -- "${BASH_SOURCE[0]}")/scripts/manage.sh" install "$@"
