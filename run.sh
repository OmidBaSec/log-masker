#!/usr/bin/env bash
#
# Run the Log Masker app in the background so it keeps running after you
# close the terminal.
#
#   ./run.sh start     start in the background on port 8888 (default)
#   ./run.sh stop      stop the background server
#   ./run.sh restart   stop then start
#   ./run.sh status     show whether it's running and on which port
#   ./run.sh logs      follow the log output (Ctrl-C to stop watching)
#   ./run.sh url       print the URL it's serving on
#
# Defaults to port 8888. To use a different port:
#   PORT=9000 ./run.sh start

set -euo pipefail

# Always operate relative to this script's own directory.
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

PID_FILE="$APP_DIR/app.pid"
PORT_FILE="$APP_DIR/app.port"   # remembers the chosen port across commands
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

# True if nothing is listening on the given TCP port.
port_is_free() {
  ! lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

start() {
  if is_running; then
    echo "Already running (PID $(cat "$PID_FILE")) on $(cat "$PORT_FILE" 2>/dev/null | sed 's#^#http://127.0.0.1:#')"
    return 0
  fi

  local port="${PORT:-8888}"
  if ! port_is_free "$port"; then
    echo "Error: port $port is already in use by:" >&2
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >&2
    exit 1
  fi

  # nohup + & detaches the process so it survives closing the terminal.
  # No --reload here: reload is for active development, not a background run.
  nohup "$UVICORN" app:app --host 127.0.0.1 --port "$port" \
    > "$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  echo "$port" > "$PORT_FILE"
  sleep 1
  if is_running; then
    echo "Started (PID $(cat "$PID_FILE")) on http://127.0.0.1:$port"
    echo "Logs: $LOG_FILE  (./run.sh logs to follow)"
  else
    echo "Failed to start. Last log lines:" >&2
    tail -n 20 "$LOG_FILE" >&2 || true
    rm -f "$PID_FILE" "$PORT_FILE"
    exit 1
  fi
}

stop() {
  if is_running; then
    local pid
    pid="$(cat "$PID_FILE")"
    kill "$pid"
    # Wait for the process to actually exit so a follow-up start doesn't
    # find the port still occupied.
    for _ in $(seq 1 20); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.25
    done
    rm -f "$PID_FILE" "$PORT_FILE"
    echo "Stopped."
  else
    echo "Not running."
    rm -f "$PID_FILE" "$PORT_FILE"
  fi
}

status() {
  if is_running; then
    echo "Running (PID $(cat "$PID_FILE")) on http://127.0.0.1:$(cat "$PORT_FILE" 2>/dev/null || echo '?')"
  else
    echo "Not running."
  fi
}

url() {
  if is_running; then
    echo "http://127.0.0.1:$(cat "$PORT_FILE" 2>/dev/null || echo '?')"
  else
    echo "Not running." >&2
    exit 1
  fi
}

case "${1:-start}" in
  start)   start ;;
  stop)    stop ;;
  restart) stop || true; start ;;
  status)  status ;;
  logs)    tail -f "$LOG_FILE" ;;
  url)     url ;;
  *)
    echo "Usage: $0 {start|stop|restart|status|logs|url}" >&2
    exit 1
    ;;
esac
