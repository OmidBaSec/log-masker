"""
Local masking / un-masking engine.

Detects sensitive tokens in raw log text and replaces each unique real value
with a stable placeholder (e.g. [EMAIL_1]). The same real value always maps to
the same placeholder, so the AI sees consistent identifiers. Un-masking is a
literal reverse substitution, so it is robust regardless of how the AI reformats
the surrounding text -- as long as the bracketed placeholders survive verbatim.

Nothing here makes a network call. Only the masked text should ever leave the
machine; the mapping stays local.
"""

import re
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# Detection patterns, ordered from most specific to least specific.
#
# Order matters: an email must be caught before its embedded domain, an API key
# before a generic hex blob, etc. Each entry is (category, label, compiled regex).
# `label` is the prefix used in the placeholder, e.g. EMAIL -> [EMAIL_1].
# ---------------------------------------------------------------------------

# Categories map to the UI checkboxes.
CATEGORIES = {
    "identities": "Usernames, emails, person names",
    "network": "Domains, hostnames, IPs, MAC addresses",
    "secrets": "API keys, tokens, UUIDs, credit cards, account numbers",
}

# A small allow-list of common domains/words we never want to mask, because
# masking them adds noise without protecting anything sensitive.
_DOMAIN_ALLOWLIST = {
    "example.com", "localhost", "anthropic.com", "api.anthropic.com",
    "google.com", "microsoft.com", "github.com",
}

# Common file extensions / TLD-lookalikes we do NOT want treated as domains.
_NOT_TLDS = {
    "py", "js", "ts", "json", "log", "txt", "md", "html", "css", "exe",
    "dll", "so", "sh", "yml", "yaml", "csv", "xml", "png", "jpg", "gif",
    "conf", "cfg", "ini", "bak", "tmp", "gz", "zip", "tar", "jar", "war",
}


def _compile_patterns():
    p: List[Tuple[str, str, "re.Pattern"]] = []

    # --- secrets / ids -----------------------------------------------------
    # Credit-card-like 13-16 digit groups (optionally separated by - or space).
    p.append(("secrets", "CC", re.compile(
        r"\b(?:\d[ -]?){13,16}\b")))
    # Known API-key shapes (Anthropic, OpenAI, AWS, GitHub, Slack, generic sk-).
    p.append(("secrets", "APIKEY", re.compile(
        r"\b(?:sk-[A-Za-z0-9_\-]{16,}"
        r"|AKIA[0-9A-Z]{16}"
        r"|gh[pousr]_[A-Za-z0-9]{20,}"
        r"|xox[baprs]-[A-Za-z0-9-]{10,}"
        r"|AIza[0-9A-Za-z\-_]{30,})\b")))
    # Bearer / token / password key=value pairs -> mask the value only.
    p.append(("secrets", "SECRET", re.compile(
        r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|auth)"
        r"\s*[=:]\s*[\"']?([^\s\"',;]+)")))
    # UUIDs.
    p.append(("secrets", "UUID", re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")))
    # Long opaque hex/base64-ish blobs (>= 32 chars) that look like secrets.
    p.append(("secrets", "HASH", re.compile(
        r"\b[A-Fa-f0-9]{32,}\b")))

    # --- identities --------------------------------------------------------
    # Emails (before domains).
    p.append(("identities", "EMAIL", re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")))
    # user / username / login / account key=value pairs.
    p.append(("identities", "USER", re.compile(
        r"(?i)(?:user(?:name)?|login|account|uid|sAMAccountName)"
        r"\s*[=:]\s*[\"']?([A-Za-z0-9._\\\-]{2,})")))
    # Windows-style DOMAIN\user.
    p.append(("identities", "USER", re.compile(
        r"\b[A-Za-z0-9\-]{2,}\\[A-Za-z0-9._\-]{2,}\b")))

    # --- network -----------------------------------------------------------
    # MAC addresses.
    p.append(("network", "MAC", re.compile(
        r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")))
    # IPv6: either compressed (contains "::") or a full 8-hextet address.
    # This deliberately avoids matching log timestamps like 10:31:02.
    p.append(("network", "IPV6", re.compile(
        r"(?<![:.\w])(?:"
        r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"          # full 8 groups
        r"|(?:[0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{0,4}::"          # compressed ...
        r"(?:[0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{1,4}"
        r")(?![:.\w])")))
    # IPv4.
    p.append(("network", "IP", re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")))
    # Bare hostnames / computer names given via a key or CLI parameter, e.g.
    #   -ComputerName SRV-DB-02 / hostname=web01 / Server: dc-01
    # These have no TLD, so the FQDN pattern below would miss them.
    p.append(("network", "HOST", re.compile(
        r"(?i)-(?:computer(?:name)?|server|hostname|node|machine)\s+"
        r"[\"']?([A-Za-z0-9][A-Za-z0-9._\-]+)")))
    p.append(("network", "HOST", re.compile(
        r"(?i)(?:computer(?:name)?|hostname|host|server|node|machine)"
        r"\s*[=:]\s*[\"']?([A-Za-z0-9][A-Za-z0-9._\-]+)")))
    # FQDN / hostnames with a real TLD (filtered against _NOT_TLDS below).
    p.append(("network", "HOST", re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,}\b")))

    return p


_PATTERNS = _compile_patterns()


def _accept(label: str, value: str) -> bool:
    """Reject false positives before we commit to masking a match."""
    v = value.strip()
    if not v:
        return False
    if label == "HOST":
        lower = v.lower()
        if lower in _DOMAIN_ALLOWLIST:
            return False
        tld = lower.rsplit(".", 1)[-1]
        if tld in _NOT_TLDS:
            return False
    if label == "CC":
        digits = re.sub(r"[ -]", "", v)
        if not (13 <= len(digits) <= 16):
            return False
    return True


def mask(text: str, enabled: List[str],
         custom_terms: List[str] = None) -> Tuple[str, Dict[str, str]]:
    """
    Return (masked_text, mapping) where mapping maps placeholder -> real value.

    `enabled` is the list of active category keys (subset of CATEGORIES).
    `custom_terms` are exact strings to always mask (case-insensitive), e.g.
    server names or codenames that no generic pattern can safely infer. They are
    matched first, so they win over the regex categories.
    """
    enabled_set = set(enabled)

    # Per-request patterns for the user's custom terms, highest priority first.
    # Longest term first so "SRV-DB-02" wins over a substring "SRV".
    patterns = list(_PATTERNS)
    for term in sorted({t.strip() for t in (custom_terms or []) if t.strip()},
                       key=len, reverse=True):
        patterns.insert(0, ("custom", "CUSTOM",
                            re.compile(re.escape(term), re.IGNORECASE)))

    # Collect non-overlapping spans to replace: (start, end, real_value, label).
    spans: List[Tuple[int, int, str, str]] = []
    taken: List[Tuple[int, int]] = []

    def overlaps(s: int, e: int) -> bool:
        for ts, te in taken:
            if s < te and e > ts:
                return True
        return False

    for category, label, pattern in patterns:
        if category != "custom" and category not in enabled_set:
            continue
        for m in pattern.finditer(text):
            # If the pattern captured a group (key=value style), mask the group.
            if m.lastindex:
                s, e = m.start(m.lastindex), m.end(m.lastindex)
            else:
                s, e = m.start(), m.end()
            real = text[s:e]
            if not _accept(label, real):
                continue
            if overlaps(s, e):
                continue
            taken.append((s, e))
            spans.append((s, e, real, label))

    # Assign stable placeholders. Same real value -> same placeholder.
    mapping: Dict[str, str] = {}              # placeholder -> real
    reverse: Dict[Tuple[str, str], str] = {}  # (label, real) -> placeholder
    counters: Dict[str, int] = {}

    # Replace from the end so earlier indices stay valid.
    spans.sort(key=lambda x: x[0], reverse=True)
    out = text
    for s, e, real, label in spans:
        key = (label, real)
        placeholder = reverse.get(key)
        if placeholder is None:
            counters[label] = counters.get(label, 0) + 1
            placeholder = f"[{label}_{counters[label]}]"
            reverse[key] = placeholder
            mapping[placeholder] = real
        out = out[:s] + placeholder + out[e:]

    return out, mapping


def unmask(text: str, mapping: Dict[str, str]) -> str:
    """Replace every placeholder in `text` with its real value."""
    if not mapping:
        return text
    # Longest placeholder first avoids any partial-overlap surprises.
    for placeholder in sorted(mapping, key=len, reverse=True):
        text = text.replace(placeholder, mapping[placeholder])
    return text
