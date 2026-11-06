#!/usr/bin/env bash
# Install Python deps for local Arkose MatchGame on any Linux host.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PY="${PYTHON_BIN:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "missing $PY" >&2
  exit 1
fi
# Debian's apt pip cannot always self-upgrade; ignore that and install deps.
"$PY" -m pip install --break-system-packages -U pip >/dev/null 2>&1 || true
"$PY" -m pip install --break-system-packages -r "$ROOT/requirements.txt"
"$PY" - <<'PY'
import importlib
need = ["curl_cffi", "Crypto", "PIL", "requests"]
for m in need:
    importlib.import_module(m if m != "PIL" else "PIL")
    print("ok", m)
PY
echo "activate deps ready"
