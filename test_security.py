"""Checks for the request guard and the platform layer.
Run: python test_security.py

These cover the two attacks a local, unauthenticated server actually faces —
CSRF from a page the analyst visits, and DNS rebinding — plus the data/secret
location rules. No network, no real data directory.
"""

import os
import tempfile

from log_masker import guard
from log_masker import keystore
from log_masker import paths


def check(name, cond):
    print(("PASS" if cond else "FAIL") + " - " + name)
    assert cond, name


class Headers(dict):
    """Case-insensitive .get(), like Starlette's Headers."""

    def get(self, key, default=None):
        return dict.get(self, key.lower(), default)


def hdr(**kw):
    return Headers({k.replace("_", "-").lower(): v for k, v in kw.items()})


# ---------------------------------------------------------------------------
# DNS rebinding — the Host header is the only thing that catches it
# ---------------------------------------------------------------------------
def test_host_check():
    check("loopback host is accepted",
          guard.check("GET", hdr(host="127.0.0.1:8888")) is None)
    check("localhost is accepted",
          guard.check("GET", hdr(host="localhost:8888")) is None)
    check("IPv6 loopback is accepted",
          guard.check("GET", hdr(host="[::1]:8888")) is None)
    check("a rebound domain is refused",
          guard.check("GET", hdr(host="evil.example")) is not None)
    check("a LAN address is refused",
          guard.check("GET", hdr(host="192.168.1.10:8888")) is not None)
    check("a missing Host is refused",
          guard.check("GET", hdr()) is not None)
    # A hostname that merely looks like "loopback + port" must not be reduced
    # to its prefix by the port-stripping logic.
    check("a host that only looks like 127.0.0.1:port is refused",
          guard.check("GET", hdr(host="127.0.0.1:8888.evil.com")) is not None)
    check("...and the same trick on a real port still works",
          guard.check("GET", hdr(host="127.0.0.1:8888")) is None)
    check("127.0.0.0/8 is loopback",
          guard.check("GET", hdr(host="127.0.0.2:8888")) is None)
    # Rebinding delivers the attacker's name in Host even for POSTs.
    check("rebound POST is refused before any origin check",
          guard.check("POST", hdr(host="evil.example",
                                  origin="http://evil.example")) is not None)


def test_allowed_hosts_env():
    os.environ[guard.ALLOWED_HOSTS_ENV] = "logmasker.internal"
    try:
        check("an operator-allowed host passes",
              guard.check("GET", hdr(host="logmasker.internal")) is None)
        check("other hosts still refused",
              guard.check("GET", hdr(host="other.internal")) is not None)
    finally:
        del os.environ[guard.ALLOWED_HOSTS_ENV]


# ---------------------------------------------------------------------------
# CSRF — a page the analyst visits must not be able to act
# ---------------------------------------------------------------------------
def test_csrf():
    local = {"host": "127.0.0.1:8888"}
    check("same-origin POST is allowed",
          guard.check("POST", Headers({**local, "origin": "http://127.0.0.1:8888",
                                       "sec-fetch-site": "same-origin"})) is None)
    check("cross-origin POST is refused",
          guard.check("POST", Headers({**local,
                                       "origin": "https://evil.example"})) is not None)
    check("cross-site fetch metadata is refused",
          guard.check("POST", Headers({**local,
                                       "sec-fetch-site": "cross-site"})) is not None)
    check("same-site (a sibling subdomain) is refused too",
          guard.check("POST", Headers({**local,
                                       "sec-fetch-site": "same-site"})) is not None)
    check("DELETE is guarded like POST",
          guard.check("DELETE", Headers({**local,
                                         "origin": "https://evil.example"})) is not None)
    check("GET is not origin-checked (same-origin policy covers reads)",
          guard.check("GET", Headers({**local,
                                      "origin": "https://evil.example"})) is None)
    # A local script has filesystem access anyway; refusing it buys nothing.
    check("a headerless client (curl, SOAR) is allowed",
          guard.check("POST", Headers(local)) is None)
    check("sec-fetch-site: none (address bar) is allowed",
          guard.check("POST", Headers({**local, "sec-fetch-site": "none"})) is None)


def test_body_limit():
    local = {"host": "127.0.0.1:8888"}
    huge = str(guard.MAX_REQUEST_BYTES + 1)
    check("an oversized body is refused",
          guard.check("POST", Headers({**local, "content-length": huge})) is not None)
    check("a normal body is fine",
          guard.check("POST", Headers({**local, "content-length": "5000"})) is None)
    check("a junk content-length does not crash the guard",
          guard.check("POST", Headers({**local, "content-length": "abc"})) is None)
    # Without a declared length the cap cannot be applied up front, so a
    # chunked body would walk straight past it.
    check("a chunked body is refused outright",
          guard.check("POST", Headers({**local,
                                       "transfer-encoding": "chunked"})) is not None)
    check("chunked is refused even on a GET",
          guard.check("GET", Headers({**local,
                                      "transfer-encoding": "chunked"})) is not None)


# ---------------------------------------------------------------------------
# Binding somewhere the network can reach
# ---------------------------------------------------------------------------
def test_startup_bind():
    check("loopback bind is fine",
          guard.startup_check(["uvicorn", "app:app", "--host", "127.0.0.1"]) is None)
    check("no --host at all is fine",
          guard.startup_check(["uvicorn", "app:app"]) is None)
    check("0.0.0.0 is refused",
          guard.startup_check(["uvicorn", "app:app", "--host", "0.0.0.0"]) is not None)
    check("--host=0.0.0.0 form is refused too",
          guard.startup_check(["uvicorn", "app:app", "--host=0.0.0.0"]) is not None)
    check("a LAN address is refused",
          guard.startup_check(["uvicorn", "--host", "10.0.0.5"]) is not None)
    os.environ[guard.ALLOW_REMOTE_ENV] = "1"
    try:
        check("an operator can override it deliberately",
              guard.startup_check(["uvicorn", "--host", "0.0.0.0"]) is None)
    finally:
        del os.environ[guard.ALLOW_REMOTE_ENV]


# ---------------------------------------------------------------------------
# Where data and secrets live
# ---------------------------------------------------------------------------
def test_data_dir_rules():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ[paths.ENV_VAR] = tmp
        paths.reset_cache()
        try:
            check("the environment variable wins", paths.data_dir() == tmp)
            check("data_file joins onto it",
                  paths.data_file("x.json") == os.path.join(tmp, "x.json"))
            check("describe() explains the choice",
                  "environment variable" in paths.describe()["source"])
        finally:
            del os.environ[paths.ENV_VAR]
            paths.reset_cache()

    # Rule 2: a directory already holding app data keeps being used, so an
    # existing install is never relocated behind the analyst's back.
    check("an existing side-by-side install is detected",
          paths._has_data(paths.CODE_DIR) is
          any(os.path.exists(os.path.join(paths.CODE_DIR, f))
              for f in paths.DATA_FILES))
    check("an empty directory is not mistaken for an install",
          not paths._has_data(tempfile.gettempdir() + os.sep + "definitely-not-here"))

    user_dir = paths._user_data_dir()
    check("the per-user directory is absolute", os.path.isabs(user_dir))
    check("it is not the code directory", user_dir != paths.CODE_DIR)


def test_secret_fallback():
    """With no OS keyring (a container, a headless Linux box), secrets must
    still round-trip through the encrypted file."""
    with tempfile.TemporaryDirectory() as tmp:
        os.environ[paths.ENV_VAR] = tmp
        paths.reset_cache()
        real_probe = keystore._keyring_ok
        keystore._keyring_ok = lambda: False        # pretend there is none
        try:
            check("set_secret falls back to the file tier",
                  keystore.set_secret("unit_test_key", "s3cr3t") == "file")
            check("the value comes back", keystore.get_secret("unit_test_key") == "s3cr3t")
            check("it is encrypted at rest",
                  b"s3cr3t" not in open(os.path.join(tmp, keystore.SECRETS_FILE), "rb").read())
            check("backend() reports the file tier",
                  keystore.backend().startswith("encrypted file"))

            os.environ["UNIT_TEST_ENV_KEY"] = "from-env"
            check("an unset secret falls through to the environment",
                  keystore.get_secret("missing_key", "UNIT_TEST_ENV_KEY") == "from-env")
            del os.environ["UNIT_TEST_ENV_KEY"]

            keystore.delete_secret("unit_test_key")
            check("delete removes it", keystore.get_secret("unit_test_key") is None)

            if os.name != "nt":
                mode = os.stat(os.path.join(tmp, keystore.MASTER_KEY_FILE)).st_mode
                check("the master key is owner-only", oct(mode)[-3:] == "600")
        finally:
            keystore._keyring_ok = real_probe
            keystore.reset_cache()
            del os.environ[paths.ENV_VAR]
            paths.reset_cache()


# ---------------------------------------------------------------------------
# Second recheck: angles the first pass did not probe
# ---------------------------------------------------------------------------
def test_host_parsing_variants():
    ok = lambda h: guard.check("GET", hdr(host=h)) is None
    check("uppercase host is accepted", ok("LOCALHOST:8888"))
    check("surrounding whitespace is tolerated", ok(" 127.0.0.1:8888 "))
    check("bare ::1 without brackets is accepted", ok("::1"))
    check("fully expanded IPv6 loopback is accepted", ok("[0:0:0:0:0:0:0:1]:8888"))
    # CPython only started calling IPv4-mapped IPv6 addresses loopback in 3.13,
    # so guard.py unwraps the mapping itself: 3.11 and 3.13 must agree here.
    check("IPv4-mapped IPv6 loopback is accepted", ok("[::ffff:127.0.0.1]:8888"))
    check("...on every Python version", guard._is_loopback_address("::ffff:127.0.0.1"))
    check("an IPv4-mapped PUBLIC address is still refused",
          not ok("[::ffff:8.8.8.8]:8888"))
    check("a trailing dot is not treated as loopback", not ok("127.0.0.1.:8888"))
    check("userinfo trick is refused", not ok("127.0.0.1@evil.example"))
    check("an empty host is refused", not ok(""))


def test_origin_must_match_the_addressed_host():
    """"Some loopback address" is not enough. Another app on the same machine
    — a dev server on :3000 — is a different origin, and on a shared or
    developer workstation it is a perfectly plausible attacker."""
    local = {"host": "127.0.0.1:8888"}
    same = lambda o: guard.check("POST", Headers({**local, "origin": o})) is None
    check("the exact origin is accepted", same("http://127.0.0.1:8888"))
    check("a different local PORT is refused", not same("http://127.0.0.1:3000"))
    check("localhost on another port is refused", not same("http://localhost:9999"))
    check("a bare name with no port is refused", not same("http://127.0.0.1"))
    # Only we can hold this port, so nothing else can present this origin;
    # the scheme is therefore not compared (a TLS-terminating proxy legitimately
    # sends https:// with a plain Host).
    check("same host:port over https is accepted", same("https://127.0.0.1:8888"))
    check("an unrelated origin is still refused", not same("https://evil.example"))

    os.environ[guard.ALLOWED_HOSTS_ENV] = "logmasker.internal"
    try:
        r = guard.check("POST", Headers({"host": "logmasker.internal",
                                         "origin": "https://logmasker.internal"}))
        check("a proxied deployment works with ALLOWED_HOSTS", r is None)
        r = guard.check("POST", Headers({"host": "logmasker.internal",
                                         "origin": "https://evil.example"}))
        check("...and still refuses other origins there", r is not None)
    finally:
        del os.environ[guard.ALLOWED_HOSTS_ENV]


def test_all_mutating_methods_are_guarded():
    local = {"host": "127.0.0.1:8888"}
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        r = guard.check(method, Headers({**local, "origin": "https://evil.example"}))
        check(f"{method} is origin-checked", r is not None)
    # A verb-tunnelling header must not turn a guarded write into a free read.
    r = guard.check("GET", Headers({**local, "x-http-method-override": "POST",
                                    "origin": "https://evil.example"}))
    check("GET is unaffected by X-HTTP-Method-Override", r is None)
    # Origin wins even when the fetch metadata claims same-origin.
    r = guard.check("POST", Headers({**local, "origin": "https://evil.example",
                                     "sec-fetch-site": "same-origin"}))
    check("a forged Sec-Fetch-Site does not rescue a bad Origin", r is not None)


def test_bind_detection_is_thorough():
    ref = lambda argv: guard.startup_check(argv) is not None
    check(":: (all IPv6 interfaces) is refused", ref(["uvicorn", "--host", "::"]))
    check("a LAN address is refused", ref(["uvicorn", "--host", "192.168.1.5"]))
    check("0.0.0.0 with other flags is refused",
          ref(["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "80"]))
    # False positives here stop the app from starting at all.
    check("uppercase LOCALHOST starts fine", not ref(["uvicorn", "--host", "LOCALHOST"]))
    check("a stray trailing space starts fine", not ref(["uvicorn", "--host", "127.0.0.1 "]))
    check("bracketed [::1] starts fine", not ref(["uvicorn", "--host", "[::1]"]))
    check("127.0.0.2 starts fine", not ref(["uvicorn", "--host", "127.0.0.2"]))

    # uvicorn reads every CLI option from UVICORN_* too, so argv alone is not
    # where the bind address is decided (verified against uvicorn itself).
    os.environ["UVICORN_HOST"] = "0.0.0.0"
    try:
        check("UVICORN_HOST=0.0.0.0 is caught even with no --host",
              ref(["uvicorn", "app:app"]))
        os.environ["UVICORN_HOST"] = "127.0.0.1"
        check("UVICORN_HOST=127.0.0.1 is fine", not ref(["uvicorn", "app:app"]))
        os.environ["UVICORN_HOST"] = "0.0.0.0"
        check("an explicit --host still wins over the environment",
              not ref(["uvicorn", "--host", "127.0.0.1"]))
    finally:
        del os.environ["UVICORN_HOST"]


def test_secret_store_survives_damage():
    """A secrets file we cannot read must degrade to "no secret", never take
    the app down — the analyst still has the environment variable path."""
    import json
    with tempfile.TemporaryDirectory() as tmp:
        os.environ[paths.ENV_VAR] = tmp
        paths.reset_cache()
        real_probe = keystore._keyring_ok
        keystore._keyring_ok = lambda: False
        try:
            keystore.set_secret("k", "v")
            path = os.path.join(tmp, keystore.SECRETS_FILE)

            with open(path, "wb") as f:
                f.write(b"not fernet ciphertext at all")
            check("a corrupt secrets file reads as empty",
                  keystore.get_secret("k") is None)
            check("...and the environment still answers",
                  keystore.get_secret("k", "PATH") is not None)

            # A rotated/replaced master key must not crash the reader either.
            with open(os.path.join(tmp, keystore.MASTER_KEY_FILE), "w") as f:
                from cryptography.fernet import Fernet
                f.write(Fernet.generate_key().decode())
            keystore.set_secret("k", "v2")
            check("the store recovers once it can write again",
                  keystore.get_secret("k") == "v2")

            check("an empty stored value does not shadow the environment",
                  keystore.get_secret("nothing_here", "PATH") is not None)
        finally:
            keystore._keyring_ok = real_probe
            keystore.reset_cache()
            del os.environ[paths.ENV_VAR]
            paths.reset_cache()


def test_data_dir_expands_user_and_relative_paths():
    with tempfile.TemporaryDirectory() as tmp:
        nested = os.path.join(tmp, "sub", "dir")
        os.environ[paths.ENV_VAR] = nested
        paths.reset_cache()
        try:
            check("a missing directory is created", os.path.isdir(paths.data_dir()))
            check("the resolved path is absolute", os.path.isabs(paths.data_dir()))
        finally:
            del os.environ[paths.ENV_VAR]
            paths.reset_cache()

    os.environ[paths.ENV_VAR] = "~"
    paths.reset_cache()
    try:
        check("a ~ path resolves to the home directory",
              paths.data_dir() == os.path.expanduser("~"))
    finally:
        del os.environ[paths.ENV_VAR]
        paths.reset_cache()


def test_misconfiguration_is_explained():
    """A misconfigured container is the most likely first contact with these
    errors, so each one has to name the variable and the offending value."""
    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.environ[paths.ENV_VAR] = path            # a file, not a directory
    paths.reset_cache()
    try:
        try:
            paths.data_dir()
            failed = False
        except RuntimeError as e:
            failed = True
            msg = str(e)
        check("pointing the data dir at a file raises RuntimeError", failed)
        check("...naming the variable", paths.ENV_VAR in msg)
        check("...and the path", path in msg)
    finally:
        os.unlink(path)
        del os.environ[paths.ENV_VAR]
        paths.reset_cache()

    with tempfile.TemporaryDirectory() as tmp:
        os.environ[paths.ENV_VAR] = tmp
        os.environ[keystore.MASTER_KEY_ENV] = "obviously-not-a-fernet-key"
        paths.reset_cache()
        real_probe = keystore._keyring_ok
        keystore._keyring_ok = lambda: False
        try:
            try:
                keystore.set_secret("k", "v")
                failed = False
            except RuntimeError as e:
                failed, msg = True, str(e)
            check("a malformed master key raises rather than losing secrets",
                  failed)
            check("...blaming the key, not the filesystem",
                  keystore.MASTER_KEY_ENV in msg and "valid Fernet key" in msg)
            check("...and showing how to generate one", "Fernet.generate_key" in msg)
        finally:
            keystore._keyring_ok = real_probe
            keystore.reset_cache()
            del os.environ[keystore.MASTER_KEY_ENV]
            del os.environ[paths.ENV_VAR]
            paths.reset_cache()


def test_empty_secrets_are_refused():
    """get_secret() treats "" as absent, so storing one would silently do
    nothing — in either tier."""
    with tempfile.TemporaryDirectory() as tmp:
        os.environ[paths.ENV_VAR] = tmp
        paths.reset_cache()
        try:
            for value in ("", None):
                try:
                    keystore.set_secret("k", value)
                    refused = False
                except ValueError:
                    refused = True
                check(f"storing {value!r} is refused", refused)
        finally:
            del os.environ[paths.ENV_VAR]
            paths.reset_cache()


def test_unicode_and_large_secrets():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ[paths.ENV_VAR] = tmp
        paths.reset_cache()
        real_probe = keystore._keyring_ok
        keystore._keyring_ok = lambda: False
        try:
            big = "ключ-" + "x" * 10000 + "-🔑"
            keystore.set_secret("u", big)
            check("a long unicode secret round-trips",
                  keystore.get_secret("u") == big)
            keystore.delete_secret("never-stored")
            check("deleting a secret that was never stored is a no-op", True)
        finally:
            keystore._keyring_ok = real_probe
            keystore.reset_cache()
            del os.environ[paths.ENV_VAR]
            paths.reset_cache()


# ---------------------------------------------------------------------------
# Findings from the vulnerability review
# ---------------------------------------------------------------------------
def test_oauth_callback_escapes_provider_text():
    """The callback page renders text that came from the identity provider, on
    the app's own origin — where injected script would be same-origin with the
    API and the guard would wave it through."""
    from log_masker import app as appmod
    from log_masker import m365

    class FakeRequest:
        query_params = {"code": "x", "state": "y"}

    real = m365.handle_callback
    try:
        m365.handle_callback = lambda *a, **k: (_ for _ in ()).throw(
            m365.M365Error('<script>alert(1)</script>'))
        page = appmod.oauth_callback(FakeRequest())
        check("markup from the provider is escaped",
              "<script>alert(1)</script>" not in page)
        check("...and shown as text instead", "&lt;script&gt;" in page)

        m365.handle_callback = lambda *a, **k: '<img src=x onerror=alert(1)>'
        page = appmod.oauth_callback(FakeRequest())
        check("a hostile UPN is escaped too", "<img src=x" not in page)
        # The page's own markup must survive escaping.
        check("the page still renders", "</html>" in page)
    finally:
        m365.handle_callback = real


def test_endpoint_validation_blocks_ssrf_targets():
    """Two providers take a URL from the analyst and the server fetches it.
    Harmless on a desktop; a network scanner once the app is exposed."""
    from log_masker import providers

    def refused(url):
        try:
            providers.validate_endpoint(url)
            return False
        except providers.ProviderError:
            return True

    check("loopback stays allowed (Ollama lives there)",
          not refused("http://127.0.0.1:11434"))
    check("a normal https endpoint is allowed",
          not refused("https://my-resource.openai.azure.com"))
    check("a hostname we cannot resolve here is allowed",
          not refused("http://ollama.internal:11434"))

    check("the AWS/GCP/Azure metadata IP is refused",
          refused("http://169.254.169.254/latest/meta-data/"))
    check("IPv6 link-local is refused", refused("http://[fe80::1]:11434"))
    check("carrier-grade NAT is refused", refused("http://100.64.0.1"))
    check("metadata.google.internal is refused",
          refused("http://metadata.google.internal"))
    check("file:// is refused", refused("file:///etc/passwd"))
    check("gopher:// is refused", refused("gopher://127.0.0.1:11211"))
    check("an empty endpoint is refused", refused(""))


def test_user_regex_validation():
    """A saved pattern runs on every future mask, so a catastrophic one does
    not cause a hiccup — it wedges every analysis until the file is edited."""
    from log_masker import masker

    def rejected(regex):
        try:
            masker.validate_user_regex(regex)
            return False
        except ValueError:
            return True

    check("a normal pattern is accepted",
          not rejected(r"\bAKIA[0-9A-Z]{16}\b"))
    check("a field-anchored pattern is accepted", not rejected(r"user=(\w+)"))
    check("an invalid regex is rejected with a message", rejected("(["))
    check("an empty pattern is rejected", rejected("   "))
    check("an absurdly long pattern is rejected",
          rejected("a" * (masker.MAX_REGEX_LENGTH + 1)))

    # Probes are derived from the pattern's own literals, because (x+x+)+y is
    # instant against a run of "a" and pathological against a run of "x".
    check("nested quantifiers are rejected", rejected(r"(a+)+$"))
    check("...whatever character they use", rejected(r"(x+x+)+y"))
    check("...including character classes", rejected(r"([a-zA-Z]+)*$"))
    check("...and \\w with optional whitespace", rejected(r"(\w+\s?)*$"))


def test_token_cache_is_never_world_readable():
    """The M365 cache holds a refresh token. It used to be created with the
    default umask and chmod-ed afterwards, leaving a window at 0644."""
    if os.name == "nt":
        print("SKIP - POSIX permissions (Windows uses ACLs)")
        return
    from log_masker import m365

    class FakeCache:
        has_state_changed = True

        def serialize(self):
            return '{"RefreshToken": {"secret": "very-secret"}}'

    with tempfile.TemporaryDirectory() as tmp:
        real = m365.CACHE_FILE
        m365.CACHE_FILE = os.path.join(tmp, "m365_token_cache.json")
        try:
            m365._save_cache(FakeCache())
            mode = oct(os.stat(m365.CACHE_FILE).st_mode)[-3:]
            check(f"the token cache is owner-only (got {mode})", mode == "600")
        finally:
            m365.CACHE_FILE = real


# ---------------------------------------------------------------------------
# Clickjacking -- the one cross-origin attack the provenance checks do not stop
# ---------------------------------------------------------------------------
def test_security_headers():
    """guard.check() refuses a cross-origin page that *acts*. Nothing in it
    refuses one that *frames*: the iframe sends the loopback Host this app
    expects, and afterwards the framed page's own requests are same-origin.
    Only the browser can decline the frame, and only if the response says so."""
    h = guard.SECURITY_HEADERS
    csp = h["Content-Security-Policy"]

    check("framing is refused by CSP", "frame-ancestors 'none'" in csp)
    check("and by the X-Frame-Options fallback", h["X-Frame-Options"] == "DENY")
    check("MIME sniffing is off", h["X-Content-Type-Options"] == "nosniff")
    check("no local URL leaks in a referrer", h["Referrer-Policy"] == "no-referrer")

    # A script-src carrying 'unsafe-inline' would let the CSP advertise a
    # protection it does not provide. Having none is the honest state until the
    # inline theme bootstrap in index.html moves out or gets a nonce.
    check("the CSP claims no script protection it cannot deliver",
          "unsafe-inline" not in csp)


def test_security_headers_are_applied_to_a_response():
    """The policy is worth nothing if the middleware forgets to attach it."""
    headers = {}
    guard.apply_security_headers(headers)
    for name in guard.SECURITY_HEADERS:
        check(f"{name} is set on a bare response", name in headers)

    # An explicit value set by a route wins: this fills gaps, it does not
    # overwrite. A route that needs a stricter CSP must be able to say so.
    headers = {"Content-Security-Policy": "default-src 'none'"}
    guard.apply_security_headers(headers)
    check("an existing header is left alone",
          headers["Content-Security-Policy"] == "default-src 'none'")
    check("and the rest are still filled in",
          headers["X-Frame-Options"] == "DENY")


if __name__ == "__main__":
    test_host_check()
    test_allowed_hosts_env()
    test_csrf()
    test_body_limit()
    test_startup_bind()
    test_data_dir_rules()
    test_secret_fallback()
    test_host_parsing_variants()
    test_origin_must_match_the_addressed_host()
    test_all_mutating_methods_are_guarded()
    test_bind_detection_is_thorough()
    test_secret_store_survives_damage()
    test_data_dir_expands_user_and_relative_paths()
    test_misconfiguration_is_explained()
    test_empty_secrets_are_refused()
    test_unicode_and_large_secrets()
    test_oauth_callback_escapes_provider_text()
    test_endpoint_validation_blocks_ssrf_targets()
    test_user_regex_validation()
    test_token_cache_is_never_world_readable()
    test_security_headers()
    test_security_headers_are_applied_to_a_response()
    print("\nAll security tests passed.")
