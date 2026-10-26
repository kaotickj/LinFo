#!/usr/bin/env bash
set -euo pipefail
LINFO_SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="$LINFO_SOURCE_DIR/src${PYTHONPATH:+:$PYTHONPATH}"
for LINFO_PYTHON in "$LINFO_SOURCE_DIR/.venv/bin/python" /usr/bin/python3 python3; do
    if command -v "$LINFO_PYTHON" >/dev/null 2>&1 && "$LINFO_PYTHON" -c 'import PyQt6.QtWidgets' >/dev/null 2>&1; then
        exec "$LINFO_PYTHON" -m linfo "$@"
    fi
done
printf '%s\n' 'LinFo requires Python 3.10+ and PyQt6.' 'On Debian 13: sudo apt install python3-pyqt6' 'Then rerun ./launch.sh. See README.md for virtual-environment installation.' >&2
exit 1
