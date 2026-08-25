#!/usr/bin/env bash
#
# Thin wrapper around cli.py, kept so existing habits (and any scripts) keep
# working. The launcher itself is Python — see cli.py — because bash, nohup,
# kill and lsof do not exist on a stock Windows box.
#
#   ./run.sh start [--open]    ./run.sh stop      ./run.sh restart
#   ./run.sh status            ./run.sh logs -f   ./run.sh url
#   ./run.sh where             # where data and secrets live on this OS
#
# PORT=9000 ./run.sh start  is still honoured.

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

# Prefer the project venv; fall back to whatever python3 is on PATH.
if [[ -x "$APP_DIR/.venv/bin/python" ]]; then
  PYTHON="$APP_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="$(command -v python3)"
else
  echo "Error: no python3 found. Create the venv first:" >&2
  echo "  python3 -m venv .venv && .venv/bin/pip install -r requirements.lock" >&2
  exit 1
fi

# No arguments: let cli.py print its usage. (Expanding an empty array under
# `set -u` is an error on the bash 3.2 that macOS still ships.)
if [[ $# -eq 0 ]]; then
  exec "$PYTHON" -m log_masker.cli
fi

# PORT=9000 ./run.sh start  ->  cli.py start --port 9000
args=("$@")
if [[ "$1" == "start" || "$1" == "restart" ]] && [[ -n "${PORT:-}" ]]; then
  args+=(--port "$PORT")
fi

exec "$PYTHON" -m log_masker.cli "${args[@]}"
