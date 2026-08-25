#!/usr/bin/env python3
"""
Log Masker launcher — one command that behaves the same on macOS, Windows and
Linux.

    log-masker start [--port 8888] [--open]     (installed console script)
    python -m log_masker.cli start              (from a checkout)
    ... stop | restart | status | logs [-n 50] [-f] | url | where

The old run.sh needed bash, nohup, kill and lsof; none of those exist on a
stock Windows box. This uses only the standard library, and identifies the
running server over HTTP (`/healthz`) rather than by trusting a pid file — so
`stop` can never kill an unrelated process that happens to hold the port, and
`status` never has to ask the OS about process liveness in a platform-specific
way.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

from log_masker import paths

DEFAULT_PORT = 8888
HOST = "127.0.0.1"
PID_FILE = "app.pid"
PORT_FILE = "app.port"
LOG_FILE = "app.log"
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
# uvicorn must import `log_masker.app`, so it runs from the directory that
# holds the package (irrelevant once installed, essential from a checkout).
CODE_DIR = os.path.dirname(PACKAGE_DIR)
IS_WINDOWS = os.name == "nt"


# ---------------------------------------------------------------------------
# Small helpers over the runtime files (all inside the data directory)
# ---------------------------------------------------------------------------
def _read(name: str) -> str:
    try:
        with open(paths.data_file(name), "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _write(name: str, value: str) -> None:
    with open(paths.data_file(name), "w", encoding="utf-8") as f:
        f.write(str(value))


def _clear(*names: str) -> None:
    for name in names:
        try:
            os.remove(paths.data_file(name))
        except OSError:
            pass


def health(port: int, timeout: float = 1.0) -> dict:
    """The /healthz payload of a Log Masker on `port`, or {} if that is not
    what is listening there."""
    try:
        with urllib.request.urlopen(
                f"http://{HOST}:{port}/healthz", timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
        return data if data.get("app") == "log-masker" else {}
    except (urllib.error.URLError, OSError, ValueError):
        return {}


def running() -> tuple:
    """(port, healthz) for the instance we started, or (0, {})."""
    port = int(_read(PORT_FILE) or 0)
    if not port:
        return 0, {}
    info = health(port)
    return (port, info) if info else (0, {})


def _free_port(port: int) -> bool:
    import socket
    with socket.socket() as s:
        # Match how uvicorn binds: without SO_REUSEADDR a socket still in
        # TIME_WAIT from the instance we just stopped looks like a busy port.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((HOST, port))
            return True
        except OSError:
            return False


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_start(args) -> int:
    port, info = running()
    if info:
        print(f"Already running (PID {info.get('pid')}) on http://{HOST}:{port}")
        if args.open:
            _open_browser(port)
        return 0

    port = args.port or int(_read(PORT_FILE) or 0) or DEFAULT_PORT
    if not _free_port(port):
        if health(port):
            print(f"Port {port} already serves a Log Masker started elsewhere.")
            return 1
        print(f"Port {port} is busy — pick another with --port.")
        return 1

    log_path = paths.data_file(LOG_FILE)
    log = open(log_path, "a", encoding="utf-8")
    cmd = [sys.executable, "-m", "uvicorn", "log_masker.app:app",
           "--host", HOST, "--port", str(port)]

    # Detach so the server outlives this shell — the flags differ per platform,
    # the intent does not.
    kwargs = {"cwd": CODE_DIR, "stdout": log, "stderr": subprocess.STDOUT,
              "stdin": subprocess.DEVNULL}
    if IS_WINDOWS:
        kwargs["creationflags"] = (subprocess.CREATE_NEW_PROCESS_GROUP |
                                   getattr(subprocess, "DETACHED_PROCESS", 0))
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(cmd, **kwargs)
    log.close()

    _write(PORT_FILE, port)
    _write(PID_FILE, proc.pid)

    for _ in range(60):                      # ~15s, uvicorn starts in ~1s
        info = health(port, timeout=0.5)
        if info:
            print(f"Started (PID {info['pid']}) on http://{HOST}:{port}")
            print(f"Data:   {info.get('data_dir')}")
            print(f"Logs:   {log_path}")
            if args.open:
                _open_browser(port)
            return 0
        if proc.poll() is not None:
            break
        time.sleep(0.25)

    print("The server did not come up. Last lines of the log:\n")
    print(_tail(log_path, 20))
    _clear(PID_FILE)
    return 1


def cmd_stop(args) -> int:
    port, info = running()
    if not info:
        print("Not running.")
        _clear(PID_FILE)
        return 0
    pid = int(info.get("pid") or 0)
    if not pid:
        print("The running server did not report a pid; stop it manually.")
        return 1

    if IS_WINDOWS:
        # No SIGTERM on Windows: taskkill ends the process tree cleanly.
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                       capture_output=True)
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            print(f"Could not stop PID {pid}: {e}")
            return 1

    for _ in range(40):                      # give it 10s to close the port
        if not health(port, timeout=0.5):
            print(f"Stopped (PID {pid}).")
            _clear(PID_FILE)
            return 0
        time.sleep(0.25)
    print(f"PID {pid} is still answering on port {port}.")
    return 1


def cmd_status(args) -> int:
    port, info = running()
    if not info:
        print("Not running.")
        return 1
    print(f"Running (PID {info['pid']}) on http://{HOST}:{port}")
    print(f"  version         {info.get('version')}")
    print(f"  python          {info.get('python')} on {info.get('platform')}")
    print(f"  data directory  {info.get('data_dir')}")
    print(f"                  ({info.get('source')})")
    print(f"  secret storage  {info.get('secret_backend')}")
    return 0


def _tail(path: str, n: int) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return "".join(f.readlines()[-n:])
    except OSError:
        return "(no log yet)"


def cmd_logs(args) -> int:
    path = paths.data_file(LOG_FILE)
    print(_tail(path, args.lines), end="")
    if not args.follow:
        return 0
    # Poll rather than shell out to `tail -f`, which Windows does not have.
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if line:
                    print(line, end="")
                else:
                    time.sleep(0.4)
    except KeyboardInterrupt:
        return 0
    except OSError:
        return 1


def cmd_url(args) -> int:
    port = int(_read(PORT_FILE) or DEFAULT_PORT)
    print(f"http://{HOST}:{port}")
    return 0


def cmd_where(args) -> int:
    info = paths.describe()
    print(f"data directory  {info['data_dir']}")
    print(f"                ({info['source']})")
    print(f"code directory  {info['code_dir']}")
    try:
        from log_masker import keystore
        print(f"secret storage  {keystore.backend()}")
    except Exception as e:                      # noqa: BLE001 - informational
        print(f"secret storage  unavailable ({e})")
    print(f"\nOverride the data directory with {paths.ENV_VAR}=<path>.")
    return 0


def _open_browser(port: int) -> None:
    import webbrowser
    webbrowser.open(f"http://{HOST}:{port}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="log-masker", description="Run Log Masker locally.")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("start", help="start the server in the background")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--open", action="store_true", help="open a browser too")
    p.set_defaults(func=cmd_start)

    sub.add_parser("stop", help="stop the server").set_defaults(func=cmd_stop)
    sub.add_parser("status", help="is it running?").set_defaults(func=cmd_status)

    p = sub.add_parser("logs", help="show the server log")
    p.add_argument("-n", "--lines", type=int, default=40)
    p.add_argument("-f", "--follow", action="store_true")
    p.set_defaults(func=cmd_logs)

    sub.add_parser("url", help="print the URL").set_defaults(func=cmd_url)
    sub.add_parser("where", help="show data + secret locations").set_defaults(
        func=cmd_where)

    p = sub.add_parser("restart", help="stop, then start")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--open", action="store_true")
    p.set_defaults(func=lambda a: (cmd_stop(a), cmd_start(a))[1])

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
