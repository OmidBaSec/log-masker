"""
Regex workbench — "why was this not masked, and what do I change?"

When a value slips through, the analyst has the one thing needed to fix it:
the line it slipped through in. Everything here turns that line into a
concrete, testable regex change, on this machine, with no provider call — the
whole point being that a log which was too sensitive to send is also too
sensitive to paste into an online regex tester.

Three steps, in the order a person would take them:

  diagnose()  Why did this value survive? There are four different answers
              ("nothing matched", "a pattern matched but the value was
              rejected", "a protected span claimed it", "an earlier pattern
              claimed it") and they lead to four different fixes. Guessing
              wrong here wastes an afternoon.
  suggest()   Given the diagnosis, propose regex edits — preferring to widen
              the built-in that *should* have caught this over adding a new
              pattern, because one more key in an existing alternation is a
              change a reviewer can read.
  try_regex() Run a candidate against the sample and show exactly what it
              would mask, before anything is saved.

Nothing here writes: applying a suggestion goes through the existing
set_builtin_pattern() / store.add_pattern(), which validate and persist.
"""

import re
from typing import Dict, List, Optional, Tuple

from . import masker

# A sample is one log line or a short excerpt, not a whole file: the point is
# to reason about the shape around one value.
MAX_SAMPLE_CHARS = 20000
MAX_SUGGESTIONS = 6


# ---------------------------------------------------------------------------
# Reading the shape around the value.
# ---------------------------------------------------------------------------

# The last token before a separator, and the indented "Field Name:" form that
# Windows event logs use. Read from the right: the key is the one *touching*
# the value, and a regex anchored at the end still prefers the leftmost start,
# which on "srcuser=jsmith assetLabel=" hands back "jsmith assetLabel".
_KEY_TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_.\-]*)$")
_KEY_FIELD_LABEL = re.compile(
    r"(?m)^[ \t]*([A-Za-z][A-Za-z0-9_.\-]*(?:[ ][A-Za-z][A-Za-z0-9_.\-]*){0,2})$")
# PowerShell: "-ComputerName ", "-Identity "
_ANCHOR_PARAM = re.compile(r"(?<![\w-])--?([A-Za-z][A-Za-z0-9\-]{1,30})[ \t]+[\"']?$")
# XML: "<MachineName>" and Windows event XML's "<Data Name='TargetUserName'>"
_ANCHOR_XML_DATA = re.compile(r"<Data Name=[\"']([A-Za-z][\w]{1,40})[\"']>$")
_ANCHOR_XML = re.compile(r"<([A-Za-z][\w.\-]{1,40})>$")

# Which label a key name implies. Checked in order, so the more specific
# fragments come first.
_KEY_LABEL_HINTS = (
    (("password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
      "credential", "passphrase"), "SECRET"),
    (("email", "mail", "upn", "smtp"), "EMAIL"),
    (("domain", "realm", "tenant", "netbios"), "DOMAIN"),
    (("host", "computer", "machine", "device", "server", "node", "asset",
      "workstation", "endpoint", "agent", "instance", "vm"), "HOST"),
    (("user", "account", "login", "logon", "sam", "principal", "actor",
      "owner", "member", "operator", "analyst", "employee", "person"), "USER"),
    (("addr", "ip"), "IP"),
    (("group", "team", "role"), "GROUP"),
    (("org", "company", "tenantname"), "ORG"),
)

_IPV4 = re.compile(r"\A(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                   r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\Z")
_EMAILISH = re.compile(r"\A[^@\s]+@[^@\s]+\.[A-Za-z]{2,}\Z")
_FQDNISH = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9\-]*(?:\.[A-Za-z0-9\-]+)+\Z")


def _label_from_key(key: str) -> Optional[str]:
    flat = re.sub(r"[^a-z]", "", key.lower())
    for fragments, label in _KEY_LABEL_HINTS:
        if any(f.replace("_", "") in flat for f in fragments):
            return label
    return None


def _label_from_value(value: str) -> str:
    if _IPV4.match(value):
        return "IP"
    if _EMAILISH.match(value):
        return "EMAIL"
    if ":" in value and re.match(r"\A[0-9A-Fa-f:]+\Z", value):
        return "IPV6"
    if "\\" in value:
        return "USER"
    if _FQDNISH.match(value):
        return "HOST"
    if re.fullmatch(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+", value) \
            and any(c.isdigit() for c in value):
        return "HOST"
    return "USER"


def _value_class(value: str, quoted: bool) -> str:
    """A character class that matches this value and values shaped like it.

    Deliberately conservative: a class wider than the value invites the very
    over-masking the built-ins spent so long removing."""
    if _IPV4.match(value):
        return r"(?:\d{1,3}\.){3}\d{1,3}"
    if quoted:
        return r"[^\"'\r\n]+"
    if re.fullmatch(r"[A-Za-z0-9._@\\\-]+", value):
        return r"[A-Za-z0-9._@\\\-]+"
    if re.fullmatch(r"[^\s\"',;]+", value):
        return r"[^\s\"',;]+"
    return r"[^\r\n]+"


def _anchor(sample: str, start: int, end: int) -> Dict[str, Optional[str]]:
    """What sits immediately before this occurrence — the thing a regex can
    hold on to. Without an anchor a pattern has only the value's own shape,
    which is how "every capitalised word" becomes a hostname."""
    before = sample[max(0, start - 120):start]
    after = sample[end:end + 2]
    quoted = bool(before[-1:] in "\"'" and after[:1] in "\"'")
    for kind, rx in (("xml_data", _ANCHOR_XML_DATA), ("xml", _ANCHOR_XML),
                     ("param", _ANCHOR_PARAM)):
        m = rx.search(before)
        if m:
            return {"kind": kind, "key": m.group(1), "sep": None,
                    "quoted": quoted}

    # key=value / "key": value / indented "Field Name:  value"
    head = before.rstrip()
    if head[-1:] in "\"'":
        head = head[:-1].rstrip()
    if head[-1:] in "=:":
        sep, head = head[-1], head[:-1].rstrip()
        if head[-1:] in "\"'":
            head = head[:-1]
        token = _KEY_TOKEN.search(head)
        key = token.group(1) if token else None
        if sep == ":":
            label_form = _KEY_FIELD_LABEL.search(head)
            if label_form and " " in label_form.group(1):
                key = label_form.group(1)
        if key:
            return {"kind": "kv", "key": key, "sep": sep, "quoted": quoted}
    return {"kind": "bare", "key": None, "sep": None, "quoted": quoted}


# ---------------------------------------------------------------------------
# Diagnosis — why did this value survive?
# ---------------------------------------------------------------------------

def _occurrences(sample: str, value: str) -> List[Tuple[int, int]]:
    out, i = [], 0
    while True:
        i = sample.find(value, i)
        if i < 0:
            return out
        out.append((i, i + len(value)))
        i += 1


def _keep_span(sample: str, start: int, end: int) -> Optional[str]:
    """The protected span covering this position, if any. A value inside one
    is not "missed" — it was deliberately kept (see masker._KEEP_PATTERNS)."""
    for keep in masker._KEEP_PATTERNS:
        for m in keep.finditer(sample):
            ks, ke = (m.span(1) if m.lastindex else m.span())
            if ks < end and start < ke:
                return sample[ks:ke]
    return None


def _why_rejected(label: str, value: str) -> str:
    """The _accept() rule that threw this value out, in words.

    Every branch here mirrors one in masker._accept and refers to the same
    data, so a value added to a list shows up in both. test_regexlab asserts
    that anything _accept rejects gets a reason, so the two cannot drift
    apart silently."""
    v = value.strip()
    if not v:
        return "the captured value is empty"
    rx = masker._PS_NOT_A_SECRET if label == "SECRET" else masker._PS_NOT_A_VALUE
    if rx.match(v):
        return ("it is PowerShell syntax — a $variable, an @{splat} or the "
                "next -Parameter — rather than a value")
    if label == "SECRET" and "-" in v \
            and v.lstrip("([{").split("-", 1)[0].lower() in masker._PS_VERBS:
        return "it is a cmdlet name (Verb-Noun), not the secret beside it"
    if v.lower() in masker._WINDOWS_BUILTIN_VALUES:
        return (f"'{v}' is a built-in Windows account, group or placeholder "
                "value that identifies nobody")
    if label in ("ASSET", "ORG") and v.lower() in masker._SAAS_APP_ALLOWLIST:
        return f"'{v}' names the SaaS vendor's product, not the customer"
    if label in ("ASSET", "ORG", "GROUP", "SUBJECT") and len(v) < 3:
        return "it is shorter than three characters, so it names nothing"
    if label in ("USER", "DOMAIN", "HOST") and v[:1] == "\\":
        return "it starts with a backslash, so it is a regex escape or a path"
    if label == "USER" and "\\" in v:
        prefix, account = v.lower().split("\\", 1)
        if prefix in masker._BUILTIN_DOMAIN_PREFIXES:
            return f"'{prefix}' is a built-in domain prefix (NT AUTHORITY, BUILTIN)"
        if prefix in masker._DOMAIN_ALLOWLIST:
            return f"'{prefix}' is on the domain allow-list"
        if account.strip("\\") in masker._WINDOWS_BUILTIN_VALUES:
            return f"'{account}' is a built-in group, not a person"
    if label in ("USER", "DOMAIN") and v.isdigit():
        return "it is all digits, which identifies nobody on its own"
    if label == "HOST":
        lower = v.lower()
        if lower in masker._DOMAIN_ALLOWLIST:
            return f"'{v}' is on the domain allow-list (a vendor console host)"
        if lower in masker._NOT_HOSTS:
            return f"'{v}' is a log level, path component or protocol name"
        if v.isdigit():
            return "it is all digits (a port, not a host)"
        tld = lower.rsplit(".", 1)[-1]
        if "." in lower and tld in masker._NOT_TLDS:
            return (f"'.{tld}' is on the not-a-TLD list — it reads as a file "
                    "extension or a JSON key suffix, not a domain")
        raw_tld = v.rsplit(".", 1)[-1]
        if "." in v and any(c.isupper() for c in raw_tld[1:]) \
                and any(c.islower() for c in raw_tld):
            return ("its last label is camelCase, which is an API or schema "
                    "namespace rather than a TLD")
    if label in ("IP", "IPV6"):
        try:
            import ipaddress
            addr = ipaddress.ip_address(v.strip("[]"))
            if addr.is_loopback or addr.is_unspecified:
                return "loopback and unspecified addresses identify no one"
        except ValueError:
            pass
    if label == "SECRET" and v.startswith("/"):
        return "it is a filesystem path (sudo's PWD=), not a password"
    if label == "CC":
        digits = re.sub(r"[ -]", "", v)
        if not (13 <= len(digits) <= 16):
            return "it is not 13-16 digits long"
        return "it fails the Luhn check digit, so it is not a card number"
    return "an _accept() rule rejected it"


def _pattern_index() -> List[Dict[str, object]]:
    """Built-in patterns with their metadata, aligned by index."""
    out = []
    for i, ((pid, src, note), (cat, label, rx)) in enumerate(
            zip(masker._PATTERN_META, masker._PATTERNS)):
        out.append({"index": i, "id": pid, "source": src, "note": note,
                    "category": cat, "label": label, "regex": rx})
    return out


def diagnose(sample: str, value: str,
             enabled: Optional[List[str]] = None) -> Dict[str, object]:
    """Why is `value` still visible after masking `sample`?"""
    sample = (sample or "")[:MAX_SAMPLE_CHARS]
    value = (value or "").strip()
    cats = set(enabled if enabled is not None else masker.CATEGORIES)

    if not value:
        return {"ok": False, "error": "Give the value that should have been "
                                      "masked."}
    spots = _occurrences(sample, value)
    if not spots:
        return {"ok": False, "error": "That value does not appear in the "
                                      "sample text, character for character."}

    masked, mapping = masker.mask(sample, sorted(cats))
    start, end = spots[0]
    anchor = _anchor(sample, start, end)
    label = (_label_from_key(anchor["key"] or "") or _label_from_value(value))

    # Everything that touched this position, in priority order.
    hits = []
    for entry in _pattern_index():
        for m in entry["regex"].finditer(sample):
            s, e = m.span(m.lastindex) if m.lastindex else m.span()
            if s < end and start < e:
                text = sample[s:e]
                accepted = masker._accept(entry["label"], text)
                hits.append({
                    "id": entry["id"], "source": entry["source"],
                    "note": entry["note"], "category": entry["category"],
                    "label": entry["label"], "matched": text,
                    "whole_value": s <= start and e >= end,
                    "accepted": accepted,
                    "category_on": entry["category"] in cats,
                    "reason": None if accepted
                              else _why_rejected(entry["label"], text),
                })
                break

    kept = _keep_span(sample, start, end)
    if value not in masked:
        verdict, detail = "already_masked", (
            "The current patterns already mask this value. If it survived in "
            "the app, check that the category is switched on for the run.")
    elif kept:
        verdict, detail = "protected", (
            f"A protected span claimed it: {kept!r}. Protected spans are "
            "never masked — see the 'deliberately not masked' list. Removing "
            "one is a change to _KEEP_PATTERNS, not to a regex.")
    elif any(h["accepted"] and h["whole_value"] and h["category_on"]
             for h in hits):
        verdict, detail = "claimed_earlier", (
            "A pattern matched and accepted it, so something with higher "
            "priority claimed the same characters first. Widening a regex "
            "will not help; the competing pattern is the one to look at.")
    elif any(h["accepted"] and not h["category_on"] for h in hits):
        verdict, detail = "category_off", (
            "A pattern matches it, but its category is switched off for this "
            "run. Turn the category on rather than editing a regex.")
    elif hits:
        verdict, detail = "rejected", (
            "A pattern matched it and then _accept() threw the value out. "
            "The fix is usually the allow-list, not the regex.")
    else:
        verdict, detail = "no_match", (
            "No built-in pattern matches these characters at all. This is "
            "the case a regex change fixes.")

    return {
        "ok": True, "verdict": verdict, "detail": detail,
        "value": value, "label": label, "occurrences": len(spots),
        "anchor": anchor, "protected_by": kept,
        "hits": hits[:MAX_SUGGESTIONS],
        "masked_preview": masked,
    }


# ---------------------------------------------------------------------------
# Building the suggestion.
# ---------------------------------------------------------------------------

def _skip_class(src: str, i: int) -> int:
    """Index just past the character class starting at src[i] == '['."""
    n, i = len(src), i + 1
    if i < n and src[i] == "^":
        i += 1
    if i < n and src[i] == "]":
        i += 1
    while i < n and src[i] != "]":
        i += 2 if src[i] == "\\" else 1
    return i + 1


def _groups(src: str) -> List[Tuple[int, int, int]]:
    """(open, body_start, close) for every '(?:' group, outermost first."""
    out, i, n = [], 0, len(src)
    while i < n:
        if src[i] == "\\":
            i += 2
        elif src[i] == "[":
            i = _skip_class(src, i)
        elif src.startswith("(?:", i):
            depth, j = 1, i + 3
            while j < n and depth:
                if src[j] == "\\":
                    j += 2
                elif src[j] == "[":
                    j = _skip_class(src, j)
                elif src[j] == "(":
                    depth += 1
                    j += 1
                elif src[j] == ")":
                    depth -= 1
                    if not depth:
                        break
                    j += 1
                else:
                    j += 1
            out.append((i, i + 3, j))
            i += 3
        else:
            i += 1
    return out


# A group that is a list of field names, as opposed to one that is matching
# the value itself. Quantifiers and wildcards say "this is the value part".
_NOT_A_KEY_LIST = set(".+*{}^$")


def _key_alternations(src: str) -> List[Tuple[int, int, int]]:
    return [g for g in _groups(src)
            if "|" in src[g[1]:g[2]]
            and not (_NOT_A_KEY_LIST & set(src[g[1]:g[2]]))]


def _key_alternative(key: str) -> str:
    """The new key, written the way the built-ins write theirs: separators
    optional, so "device name" also covers device_name and devicename."""
    parts = [re.escape(p) for p in re.split(r"[ _\-]+", key.strip()) if p]
    return r"[ _\-]?".join(parts)


def _would_mask(sample: str, cats: List[str], value: str,
                patch: Optional[Dict[str, str]] = None,
                extra: Optional[Dict[str, str]] = None) -> Tuple[bool, List[str]]:
    """Mask `sample` with a candidate applied, without saving anything.

    Returns (the value is gone, values newly masked that were not before)."""
    before = set(masker.mask(sample, cats)[1].values())
    masked, mapping = masker.mask(
        sample, cats,
        custom_patterns=[extra] if extra else None,
        builtin_patches=patch)
    return value not in masked, sorted(set(mapping.values()) - before)


def _matches_here(regex: str, sample: str, start: int, end: int) -> bool:
    """Does this candidate capture the value at the position it occupies?"""
    try:
        compiled = re.compile(regex)
    except re.error:
        return False
    for m in compiled.finditer(sample):
        s, e = m.span(m.lastindex) if m.lastindex else m.span()
        if s <= start and e >= end:
            return True
    return False


# Several built-ins can be widened to catch the same value, and all of them
# verify. Prefer the one written for the shape the value actually sits in: a
# parameter belongs in the parameter pattern, not in the one for prose.
_ANCHOR_FIT = {
    "kv": ("[=:]", "=\\s", ":\\s", "\\s*[=:]"),
    "param": ("-(?:", "--?", "-(?i:"),
    "xml": ("<",),
    "xml_data": ("<Data",),
}


def _anchor_fit(anchor: Dict[str, Optional[str]], src: str) -> bool:
    kind, key = anchor["kind"], anchor["key"] or ""
    # "  Requesting Workstation:   WS-FIN-07" is a field label on its own line,
    # which is a different pattern family from "host=x" even though both end
    # in a colon. Line anchoring is what tells them apart.
    if kind == "kv" and " " in key:
        return "(?im)^" in src or "(?m)^" in src
    return any(token in src for token in _ANCHOR_FIT.get(kind, ()))


def _proposal(kind: str, label: str, regex: str, why: str, **extra) -> Dict:
    out = {"kind": kind, "label": label, "regex": regex, "why": why}
    out.update(extra)
    return out


def suggest(sample: str, value: str, label: Optional[str] = None,
            enabled: Optional[List[str]] = None) -> Dict[str, object]:
    """Diagnose, then propose regex changes that would have caught `value`.

    Ordered by how small the change is: widening the key list of the built-in
    that already covers this field beats a brand-new pattern, because it keeps
    one rule per idea and stays reviewable."""
    report = diagnose(sample, value, enabled)
    if not report.get("ok"):
        return report
    if report["verdict"] not in ("no_match", "rejected"):
        report["suggestions"] = []
        return report

    cats = sorted(enabled if enabled is not None else masker.CATEGORIES)
    label = label or report["label"]
    anchor = report["anchor"]
    key = anchor["key"]
    sample = sample[:MAX_SAMPLE_CHARS]
    value = value.strip()
    vclass = _value_class(value, bool(anchor["quoted"]))
    here = _occurrences(sample, value)[0]
    proposals: List[Dict] = []

    # 1. Widen the built-in that already handles this kind of field.
    if key and anchor["kind"] in ("kv", "param", "xml", "xml_data"):
        alt = _key_alternative(key)
        for entry in _pattern_index():
            if entry["label"] != label:
                continue
            src = entry["regex"].pattern
            if re.search(r"(?<![\w])" + re.escape(key.lower()), src.lower()):
                continue                      # the key is in there already
            for open_idx, body, _close in _key_alternations(src):
                candidate = src[:body] + alt + "|" + src[body:]
                try:
                    masker.validate_user_regex(candidate)
                except ValueError:
                    continue
                if not _matches_here(candidate, sample, *here):
                    continue
                ok, extra_hits = _would_mask(
                    sample, cats, value, patch={entry["id"]: candidate})
                if not ok:
                    continue
                proposals.append(_proposal(
                    "extend_builtin", label, candidate,
                    f"Adds “{key}” to the field list of the “{entry['source']}”"
                    f" pattern, which already masks this kind of value.",
                    id=entry["id"], source=entry["source"],
                    note=entry["note"], current_regex=src,
                    side_effects=extra_hits,
                    fit=_anchor_fit(anchor, src)))
                break
        # Best fit first, then the edit with the fewest side effects.
        proposals.sort(key=lambda pr: (not pr.get("fit"),
                                       len(pr.get("side_effects") or [])))
        del proposals[2:]

    # 2. A new pattern built from the shape around the value.
    new_regex = None
    if anchor["kind"] == "kv" and key:
        new_regex = (r"(?i)" + _key_alternative(key)
                     + r"[\"']?\s*[=:]\s*[\"']?(" + vclass + ")")
        why = f"Matches “{key}” followed by = or :, masking only the value."
    elif anchor["kind"] == "param" and key:
        new_regex = (r"(?i)(?<![\w-])--?" + re.escape(key)
                     + r"[ \t]+[\"']?(" + vclass + ")")
        why = f"Matches the argument of the -{key} parameter."
    elif anchor["kind"] == "xml_data" and key:
        new_regex = (r"(?i)<Data Name=[\"']" + re.escape(key)
                     + r"[\"']>([^<]+)</Data>")
        why = f"Matches the <Data Name='{key}'> element of a Windows event."
    elif anchor["kind"] == "xml" and key:
        new_regex = r"(?i)<" + re.escape(key) + r">([^<]+)<"
        why = f"Matches the <{key}> element."
    if new_regex:
        try:
            masker.validate_user_regex(new_regex)
            ok, extra_hits = _would_mask(
                sample, cats, value,
                extra={"label": label, "regex": new_regex})
            if ok and _matches_here(new_regex, sample, *here):
                proposals.append(_proposal(
                    "new_pattern", label, new_regex, why,
                    side_effects=extra_hits))
        except ValueError:
            pass

    # 3. Last resort: the value itself. Honest about what it is — this masks
    #    one string and nothing else, which is what "custom terms" is for.
    literal = masker._exact_known_pattern(value).pattern
    ok, extra_hits = _would_mask(sample, cats, value,
                                 extra={"label": label, "regex": literal})
    if ok:
        proposals.append(_proposal(
            "literal", label, literal,
            "Masks this exact value and nothing else. Prefer a custom term "
            "for this — it is the same thing without a regex to maintain.",
            side_effects=extra_hits, weak=True))

    report["suggestions"] = proposals[:MAX_SUGGESTIONS]
    return report


def try_regex(sample: str, regex: str, label: str = "CUSTOM",
              enabled: Optional[List[str]] = None) -> Dict[str, object]:
    """Run one candidate against the sample and show what it would mask."""
    sample = (sample or "")[:MAX_SAMPLE_CHARS]
    try:
        regex = masker.validate_user_regex(regex)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    compiled = re.compile(regex)
    matches = []
    for m in compiled.finditer(sample):
        s, e = m.span(m.lastindex) if m.lastindex else m.span()
        text = sample[s:e]
        matches.append({"start": s, "end": e, "text": text,
                        "accepted": masker._accept(label, text),
                        "reason": None if masker._accept(label, text)
                                  else _why_rejected(label, text)})
        if len(matches) >= 200:
            break

    cats = sorted(enabled if enabled is not None else masker.CATEGORIES)
    before = masker.mask(sample, cats)[1]
    masked, mapping = masker.mask(
        sample, cats, custom_patterns=[{"label": label, "regex": regex}])
    return {
        "ok": True, "regex": regex, "label": label,
        "matches": matches,
        "newly_masked": sorted(set(mapping.values()) - set(before.values())),
        "preview": masked,
    }
