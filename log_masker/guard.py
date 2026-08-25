"""
Request guard for a local, unauthenticated server.

Log Masker listens on 127.0.0.1 with no login — which is the right design for a
single-analyst desktop tool, and also means the browser is the attack surface.
Two classic attacks apply, and neither needs the attacker to be on the network:

  * **CSRF.** Any page the analyst visits can issue cross-origin requests to
    http://127.0.0.1:8888. It cannot *read* the responses, but it can act:
    change masking rules, delete a key, or send a log to a provider.
  * **DNS rebinding.** An attacker's domain resolves first to their server, then
    to 127.0.0.1. Their page is now "same-origin" with this app as far as the
    browser is concerned, so it can read responses too — including the vault.

The defence is provenance, not authentication:

  1. The ``Host`` header must name a loopback address. A rebound request arrives
     as ``Host: evil.example``, so it is refused before it reaches a route. This
     is what stops rebinding; an origin check alone would not.
  2. State-changing requests must not come from another origin. Browsers attach
     ``Origin`` to every non-GET request and ``Sec-Fetch-Site`` to all of them,
     so cross-site attempts identify themselves.
  3. A request with no browser provenance at all (curl, a SOAR script, the test
     suite) is allowed. That is deliberate: the boundary being defended is "a
     web page the analyst happens to visit", not "code already running as the
     analyst" — such code can read the data directory directly, so refusing it
     here would buy nothing and break scripting.

GET requests are only Host-checked: they change no state, and cross-origin reads
are already blocked by the same-origin policy (no CORS headers are ever sent).
"""

import ipaddress
import os
from typing import Iterable, Optional, Set
from urllib.parse import urlsplit

ALLOW_REMOTE_ENV = "LOGMASKER_ALLOW_REMOTE"
ALLOWED_HOSTS_ENV = "LOGMASKER_ALLOWED_HOSTS"

# Nothing legitimate posts more than this: a 25 MB log is already far past what
# an analyst pastes, and an unbounded body is a free way to exhaust memory on a
# server with no login in front of it.
MAX_REQUEST_BYTES = int(os.environ.get("LOGMASKER_MAX_REQUEST_MB", "25")) * 1024 * 1024

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Names that always mean "this machine", plus whatever an operator adds when
# they deliberately expose the app (see ALLOW_REMOTE_ENV).
_LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1", "[::1]",
                             "0.0.0.0", "ip6-localhost"})


def _extra_hosts() -> Set[str]:
    raw = os.environ.get(ALLOWED_HOSTS_ENV, "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _hostname(value: str) -> str:
    """The host part of a Host header or an Origin URL, port and brackets off."""
    value = (value or "").strip().lower()
    if "://" in value:
        value = urlsplit(value).netloc
    if value.startswith("["):                      # [::1]:8888
        end = value.find("]")
        return value[1:end] if end != -1 else value.strip("[]")
    # Strip a port only when it really is one: "127.0.0.1:8888.evil.com" is a
    # hostname that merely looks like a loopback address with a port, and must
    # not be reduced to "127.0.0.1".
    if value.count(":") == 1:
        head, _, tail = value.rpartition(":")
        if tail.isdigit():
            return head
    return value


def _is_loopback_address(host: str) -> bool:
    """Whether `host` is a loopback IP literal.

    Not simply `ip_address(host).is_loopback`: CPython only began reporting
    IPv4-mapped IPv6 addresses (``::ffff:127.0.0.1``) as loopback in 3.13, so
    leaning on the stdlib would have 3.11 and 3.13 disagree about who may reach
    this server. Unwrap the mapping ourselves and get one answer everywhere.
    """
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped.is_loopback if mapped is not None else addr.is_loopback


def is_local_host(value: str, allowed: Optional[Iterable[str]] = None) -> bool:
    """True when `value` names this machine (or an explicitly allowed host)."""
    host = _hostname(value)
    if not host:
        return False
    if host in _LOOPBACK_NAMES:
        return True
    if host in (set(allowed) if allowed else _extra_hosts()):
        return True
    return _is_loopback_address(host)


def _netloc(value: str) -> str:
    """host:port of a Host header or an Origin URL, lowercased."""
    value = (value or "").strip().lower()
    if "://" in value:
        value = urlsplit(value).netloc
    return value


def _origin_matches(origin: str, host_header: str) -> bool:
    """An Origin is acceptable only when it names the very host:port the
    request was addressed to. "Some loopback address" is not enough: another
    app on the same machine — a dev server on :3000, say — is a different
    origin and must not be able to drive this one."""
    if _netloc(origin) == _netloc(host_header) and _netloc(origin):
        return True
    # A reverse proxy may terminate TLS and present a different port, so an
    # operator-allowed hostname matches on the name alone.
    return _hostname(origin) in _extra_hosts()


def _is_loopback_bind(host: str) -> bool:
    """For *binding*, only true loopback counts — 0.0.0.0 and :: mean
    'every interface', which is exactly what we are refusing."""
    host = (host or "").strip().lower().strip("[]")
    if not host:
        return True                       # uvicorn's own default is 127.0.0.1
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    return _is_loopback_address(host)


def check(method: str, headers) -> Optional[str]:
    """None when the request may proceed, else the reason to refuse it.
    `headers` is anything with a case-insensitive .get() (Starlette's Headers)."""
    # A chunked body declares no length, so the cap below cannot be applied
    # before the whole thing has been read — which is the attack. Nothing that
    # talks to this app streams: browsers set Content-Length for fetch bodies
    # and for FormData uploads, and so does `requests` for ordinary payloads.
    if "chunked" in (headers.get("transfer-encoding") or "").lower():
        return ("Chunked request bodies are not accepted; send Content-Length "
                "so the size limit can be enforced.")
    try:
        if int(headers.get("content-length") or 0) > MAX_REQUEST_BYTES:
            return (f"Request body is larger than the "
                    f"{MAX_REQUEST_BYTES // (1024 * 1024)} MB limit.")
    except (TypeError, ValueError):
        pass

    if not is_local_host(headers.get("host", "")):
        return ("This server only answers requests addressed to localhost. "
                f"Set {ALLOWED_HOSTS_ENV} if you are deliberately exposing it "
                "behind a reverse proxy.")

    if method.upper() in SAFE_METHODS:
        return None

    # Modern browsers label every request with where it came from.
    site = (headers.get("sec-fetch-site") or "").lower()
    if site and site not in ("same-origin", "none"):
        return f"Cross-site {method} requests are refused (Sec-Fetch-Site: {site})."

    origin = headers.get("origin") or ""
    if origin and not _origin_matches(origin, headers.get("host", "")):
        return f"Cross-origin {method} requests are refused (Origin: {origin})."

    return None


def startup_check(argv: Optional[list] = None) -> Optional[str]:
    """Refuse to start on a non-loopback interface unless the operator has said
    so. Returns an error message, or None when the bind address is fine.

    There is no authentication in front of these routes: binding 0.0.0.0 without
    understanding that hands the vault to the network."""
    import sys
    argv = sys.argv if argv is None else argv
    host = ""
    for i, arg in enumerate(argv):
        if arg == "--host" and i + 1 < len(argv):
            host = argv[i + 1]
        elif arg.startswith("--host="):
            host = arg.split("=", 1)[1]
    # uvicorn's CLI also takes every option from UVICORN_*-prefixed environment
    # variables, so a container or a shell profile can bind every interface
    # without --host ever appearing on the command line.
    if not host:
        host = os.environ.get("UVICORN_HOST", "")
    if _is_loopback_bind(host):
        return None
    if os.environ.get(ALLOW_REMOTE_ENV, "").strip().lower() in ("1", "true", "yes"):
        return None
    return (
        f"Refusing to bind {host}: Log Masker has no authentication, so any "
        "reachable machine could read the entity vault and use your API keys. "
        "Put it behind an authenticating reverse proxy and set "
        f"{ALLOW_REMOTE_ENV}=1, plus {ALLOWED_HOSTS_ENV}=<your hostname>."
    )
