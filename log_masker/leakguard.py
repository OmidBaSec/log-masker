"""
Pre-send leak guard.

A second, INDEPENDENT pass over the already-masked text, run before anything
is sent to an AI provider. It deliberately does not reuse the masking engine's
patterns: its own hardcoded detectors catch the failure modes the masker
itself cannot see — a partially-masked value, a broken user-edited regex
override, a custom term that slipped through, or a secret-shaped token no
pattern knew about.

Findings:
  high   -> blocks the send until the analyst explicitly acknowledges
  medium -> shown as warnings (review recommended, not blocking)

Everything here runs locally; findings reference substrings of the masked
payload only.
"""

import ipaddress
import math
import re
from collections import Counter
from typing import Dict, List, Optional

MAX_FINDINGS = 25

# Independent (not shared with masker.py) detectors.
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_LONG_HEX = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
_SECRETISH = re.compile(r"\b[A-Za-z0-9+/_\-]{20,}\b")
# Uppercase, dashed, digit-bearing tokens that look like asset names
# (WS-FIN-07, SRV-DB-99). The lookbehind skips Cisco %ASA-6-... codes and
# path/word continuations.
_HOSTISH = re.compile(r"(?<![%\w.\-/\\])[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+\b")

# Benign tokens that match the host-ish shape.
_SAFE_TOKENS = {
    "utf-8", "iso-8859-1", "sha-1", "sha-256", "sha-384", "sha-512",
    "aes-128", "aes-192", "aes-256", "rsa-2048", "rsa-4096", "tls-1",
    "ssl-3", "http-1", "http-2", "oauth-2", "crc-32", "base-64",
    "e-164", "rfc-5424", "iso-27001", "soc-2", "pci-dss", "x-509",
}
_SAFE_PREFIXES = ("cve-", "ms-", "kb-", "rfc-", "ta00", "t10", "t11",
                  "t12", "t13", "t14", "t15", "t16")


def _is_loopback(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_unspecified


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _boundary(value: str) -> "re.Pattern":
    pat = re.escape(value)
    if value[:1].isalnum() or value[:1] == "_":
        pat = r"(?<!\w)" + pat
    if value[-1:].isalnum() or value[-1:] == "_":
        pat = pat + r"(?!\w)"
    return re.compile(pat)


def scan(masked: str,
         mapping: Optional[Dict[str, str]] = None,
         custom_terms: Optional[List[str]] = None,
         enabled: Optional[List[str]] = None) -> List[dict]:
    """Scan MASKED text for residue that may still identify the customer.

    `enabled` is the list of active masking categories; checks belonging to a
    category the analyst deliberately switched off are skipped (otherwise
    every IP would be flagged when network masking is off by choice).
    """
    text = masked or ""
    if not text.strip():
        return []
    cats = set(enabled) if enabled is not None else {
        "identities", "network", "secrets"}
    findings: List[dict] = []
    flagged = set()           # (type, value-lower) de-dup

    def add(ftype: str, severity: str, value: str, count: int, detail: str):
        key = (ftype, value.lower())
        if key in flagged or len(findings) >= MAX_FINDINGS:
            return
        flagged.add(key)
        findings.append({"type": ftype, "severity": severity, "value": value,
                         "count": count, "detail": detail})

    # 1. Values that WERE masked somewhere but still appear verbatim — the
    #    partial-masking bug class. Strongest possible signal.
    for ph, real in (mapping or {}).items():
        if len(real) < 4 or real.isdigit():
            continue
        hits = _boundary(real).findall(text)
        if hits:
            add("known_value", "high", real, len(hits),
                f"Masked elsewhere as {ph}, but still visible "
                f"{len(hits)}× in this text.")

    # 2. Custom always-mask terms that survived.
    for term in {t.strip() for t in (custom_terms or []) if t.strip()}:
        if len(term) < 3:
            continue
        hits = re.findall(_boundary(term).pattern, text, re.IGNORECASE)
        if hits:
            add("custom_term", "high", term, len(hits),
                "Listed under custom terms to always mask, "
                "but still visible.")

    # 3. IP / email leftovers (skipped when that category is off by choice).
    if "network" in cats:
        for val, count in Counter(_IPV4.findall(text)).items():
            # The masker keeps loopback on purpose — every host is 127.0.0.1
            # to itself — so blocking the send over it would put a hard stop
            # in front of every "Get-NetTCPConnection" paste.
            if _is_loopback(val):
                continue
            add("ip_address", "high", val, count,
                "Looks like an IPv4 address that escaped masking.")
    if "identities" in cats:
        for val, count in Counter(_EMAIL.findall(text)).items():
            add("email", "high", val, count,
                "Looks like an email address that escaped masking.")

    # 4. Secret-shaped tokens (long, mixed letters+digits, high entropy).
    if "secrets" in cats:
        for val, count in Counter(_LONG_HEX.findall(text)).items():
            add("secret_like", "medium", val, count,
                "Long hex blob (hash/key material?) left unmasked.")
        seen_secret = set()
        for m in _SECRETISH.finditer(text):
            tok = m.group(0)
            if tok in seen_secret:
                continue
            seen_secret.add(tok)
            if not (any(c.isdigit() for c in tok)
                    and any(c.isalpha() for c in tok)):
                continue
            if _entropy(tok) < 3.3:
                continue
            # WMI/CIM class names are long, mixed and high-entropy, and every
            # PowerShell paste is full of them.
            if tok.startswith(("Win32_", "MSFT_", "CIM_", "Msvm_")):
                continue
            add("secret_like", "medium", tok, text.count(tok),
                "High-entropy token — possible credential or API key.")

    # 5. Asset-name-shaped tokens (uppercase, dashed, with digits).
    if "network" in cats:
        for m in _HOSTISH.finditer(text):
            tok = m.group(0)
            low = tok.lower()
            if low in _SAFE_TOKENS or low.startswith(_SAFE_PREFIXES):
                continue
            if not any(c.isdigit() for c in tok):
                continue
            add("host_like", "medium", tok, text.count(tok),
                "Looks like a hostname / asset name (uppercase with "
                "dashes and digits).")

    order = {"high": 0, "medium": 1}
    findings.sort(key=lambda f: (order.get(f["severity"], 2), f["type"]))
    return findings


def has_blocking(findings: List[dict]) -> bool:
    return any(f["severity"] == "high" for f in findings)
