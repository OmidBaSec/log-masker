"""Checks for the cross-platform launcher (cli.py).
Run: python test_cli.py

The launcher is the one piece of this app that behaves differently per OS, so
it is the piece most likely to rot silently. These tests start and stop real
servers on a scratch port with a scratch data directory — nothing here touches
the analyst's own instance, vault or audit log.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
# Derived from the pid so parallel runs (and a developer's own instance on
# 8888) never collide.
PORT = 9000 + (os.getpid() % 900)


def check(name, cond):
    print(("PASS" if cond else "FAIL") + " - " + name)
    assert cond, name


def cli(*args, data_dir=None, env=None, timeout=60):
    """Run `python cli.py ...` against a scratch data directory."""
    environ = dict(os.environ)
    environ["LOGMASKER_DATA_DIR"] = data_dir
    environ.pop("PORT", None)
    if env:
        environ.update(env)
    return subprocess.run([sys.executable, "cli.py", *args], cwd=HERE,
                          capture_output=True, text=True, timeout=timeout,
                          env=environ)


def healthz(port, timeout=1.0):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz",
                                    timeout=timeout) as r:
            return json.loads(r.read().decode())
    except (urllib.error.URLError, OSError, ValueError):
        return {}


def test_lifecycle():
    with tempfile.TemporaryDirectory() as data:
        try:
            r = cli("status", data_dir=data)
            check("status reports 'not running' before anything starts",
                  "Not running" in r.stdout)
            check("...and exits non-zero", r.returncode != 0)

            r = cli("start", "--port", str(PORT), data_dir=data)
            check("start reports the port it took", f"{PORT}" in r.stdout)
            info = healthz(PORT, timeout=5)
            check("the server actually answers /healthz", info.get("ok") is True)
            check("it runs from the scratch data directory",
                  info.get("data_dir") == data)

            r = cli("status", data_dir=data)
            check("status finds it", "Running" in r.stdout)
            check("...and exits zero", r.returncode == 0)
            check("status names the data directory", data in r.stdout)

            r = cli("start", "--port", str(PORT), data_dir=data)
            check("a second start does not launch a duplicate",
                  "Already running" in r.stdout)

            r = cli("url", data_dir=data)
            check("url prints the address", f"http://127.0.0.1:{PORT}" in r.stdout)

            r = cli("stop", data_dir=data)
            check("stop reports the pid it stopped", "Stopped" in r.stdout)
            check("the port is released", not healthz(PORT))

            r = cli("stop", data_dir=data)
            check("stopping twice is harmless", r.returncode == 0)
        finally:
            cli("stop", data_dir=data)


def test_stop_never_kills_a_stranger():
    """`stop` identifies the server over HTTP rather than trusting the pid
    file, so a stale file pointing at someone else's process cannot make it
    kill that process. This is the reason cli.py does not use psutil."""
    with tempfile.TemporaryDirectory() as data:
        # A plain HTTP server that is emphatically not Log Masker.
        victim = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(PORT), "--bind", "127.0.0.1"],
            cwd=data, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(40):
                if healthz(PORT) or _port_answers(PORT):
                    break
                time.sleep(0.25)
            check("the decoy is listening", _port_answers(PORT))

            # A stale pid/port file pointing straight at it.
            with open(os.path.join(data, "app.port"), "w") as f:
                f.write(str(PORT))
            with open(os.path.join(data, "app.pid"), "w") as f:
                f.write(str(victim.pid))

            r = cli("stop", data_dir=data)
            check("stop refuses to act on a process that is not ours",
                  "Not running" in r.stdout)
            check("the stranger is still alive", victim.poll() is None)

            r = cli("start", "--port", str(PORT), data_dir=data)
            check("start refuses to fight for a busy port",
                  "busy" in r.stdout.lower())
            check("the stranger survived that too", victim.poll() is None)
        finally:
            victim.terminate()
            victim.wait(timeout=10)


def _port_answers(port):
    import socket
    with socket.socket() as s:
        s.settimeout(1)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except OSError:
            return False


def test_where_and_logs():
    with tempfile.TemporaryDirectory() as data:
        r = cli("where", data_dir=data)
        check("where names the data directory", data in r.stdout)
        check("where explains why that directory was chosen",
              "environment variable" in r.stdout)
        check("where reports the secret backend", "secret storage" in r.stdout)

        r = cli("logs", data_dir=data)
        check("logs is graceful when there is no log yet",
              r.returncode == 0 and "no log yet" in r.stdout)


def test_bad_input_is_handled():
    with tempfile.TemporaryDirectory() as data:
        r = cli("frobnicate", data_dir=data)
        check("an unknown command prints usage", "usage:" in r.stderr.lower())
        check("...and exits non-zero", r.returncode != 0)

        r = cli("start", "--port", "notanumber", data_dir=data)
        check("a non-numeric port is rejected clearly",
              "invalid int value" in r.stderr)

        r = cli(data_dir=data)
        check("no arguments prints usage rather than failing",
              "usage:" in r.stdout.lower() and r.returncode == 0)


def test_refuses_to_expose_the_network():
    """The launcher always pins 127.0.0.1, but a user running uvicorn directly
    must be stopped — including via the environment, which uvicorn also reads."""
    with tempfile.TemporaryDirectory() as data:
        env = dict(os.environ)
        env["LOGMASKER_DATA_DIR"] = data
        env["UVICORN_HOST"] = "0.0.0.0"
        env.pop("LOGMASKER_ALLOW_REMOTE", None)
        r = subprocess.run([sys.executable, "-c", "import app"], cwd=HERE,
                           capture_output=True, text=True, env=env, timeout=60)
        check("importing the app with UVICORN_HOST=0.0.0.0 fails",
              r.returncode != 0)
        check("...with an explanation, not a traceback alone",
              "Refusing to bind" in r.stderr)
        check("...that names the escape hatch",
              "LOGMASKER_ALLOW_REMOTE" in r.stderr)


if __name__ == "__main__":
    test_lifecycle()
    test_stop_never_kills_a_stranger()
    test_where_and_logs()
    test_bad_input_is_handled()
    test_refuses_to_expose_the_network()
    print("\nAll CLI tests passed.")
