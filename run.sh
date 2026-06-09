#!/usr/bin/env bash
#
# Run the Log Masker app in the background so it keeps running after you
# close the terminal.
#
#   ./run.sh start     start in the background (default if no command given)
#   ./run.sh stop      stop the background server
#   ./run.sh restart   stop then start
#   ./run.sh status     show whether it's running
#   ./run.sh logs      follow the log output (Ctrl-C to stop watching)
#
# Open http://127.0.0.1:$PORT once started.

set -euo pipefail

# Always operate relative to this script's own directory.
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

PORT="${PORT:-8000}"          # override with: PORT=9000 ./run.sh start
PID_FILE="$APP_DIR/app.pid"
LOG_FILE="$APP_DIR/app.log"
VENV_UVICORN="$APP_DIR/.venv/bin/uvicorn"

# Prefer the venv's uvicorn; fall back to whatever is on PATH.
if [[ -x "$VENV_UVICORN" ]]; then
  UVICORN="$VENV_UVICORN"
elif command -v uvicorn >/dev/null 2>&1; then
  UVICORN="$(command -v uvicorn)"
else
  echo "Error: uvicorn not found. Create the venv and install deps first:" >&2
  echo "  python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt" >&2
  exit 1
fi

is_running() {
  [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

start() {
  if is_running; then
    echo "Already running (PID $(cat "$PID_FILE")) on http://127.0.0.1:$PORT"
    return 0
  fi
  # nohup + & detaches the process so it survives closing the terminal.
  # No --reload here: reload is for active development, not a background run.
  nohup "$UVICORN" app:app --host 127.0.0.1 --port "$PORT" \
    > "$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  sleep 1
  if is_running; then
    echo "Started (PID $(cat "$PID_FILE")) on http://127.0.0.1:$PORT"
    echo "Logs: $LOG_FILE  (./run.sh logs to follow)"
  else
    echo "Failed to start. Last log lines:" >&2
    tail -n 20 "$LOG_FILE" >&2 || true
    rm -f "$PID_FILE"
    exit 1
  fi
}

stop() {
  if is_running; then
    kill "$(cat "$PID_FILE")"
    rm -f "$PID_FILE"
    echo "Stopped."
  else
    echo "Not running."
    rm -f "$PID_FILE"
  fi
}

status() {
  if is_running; then
    echo "Running (PID $(cat "$PID_FILE")) on http://127.0.0.1:$PORT"
  else
    echo "Not running."
  fi
}

case "${1:-start}" in
  start)   start ;;
  stop)    stop ;;
  restart) stop || true; start ;;
  status)  status ;;
  logs)    tail -f "$LOG_FILE" ;;
  *)
    echo "Usage: $0 {start|stop|restart|status|logs}" >&2
    exit 1
    ;;
esac
