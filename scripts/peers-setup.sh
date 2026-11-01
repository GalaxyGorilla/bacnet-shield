#!/bin/sh
# peers-setup.sh — provision the independent BACnet stack used by the
# interop suite (bacpypes3 in .venv). Exit 77 when no Python is available, so
# the gate can distinguish "not installed" from "broken".
#
#   make peers
set -eu
cd "$(dirname "$0")/.."

PY=".venv/bin/python"
if [ -x "$PY" ] && "$PY" -c 'import bacpypes3' 2>/dev/null; then
	echo "bacpypes3 already installed: $("$PY" -c 'import bacpypes3; print(bacpypes3.__version__)')"
	exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
	echo "python3 not found; cannot provision the BACnet peer (exit 77)"
	exit 77
fi

echo "creating .venv"
python3 -m venv .venv || exit 77
.venv/bin/pip install --quiet --upgrade pip >/dev/null 2>&1 || true
echo "installing bacpypes3"
if ! .venv/bin/pip install --quiet 'bacpypes3==0.0.110'; then
	echo "pip install bacpypes3 failed (exit 77)"
	exit 77
fi

"$PY" -c 'import bacpypes3; print("bacpypes3", bacpypes3.__version__, "installed")'
