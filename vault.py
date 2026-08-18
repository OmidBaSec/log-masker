"""
Persistent entity vault — cross-incident placeholder memory.

Without the vault, placeholder numbering restarts with every conversation:
WS-FIN-07 is [HOST_1] today and [HOST_3] tomorrow. The vault makes every
placeholder stable across ALL analyses on this machine, forever: once
WS-FIN-07 becomes [HOST_12], it is [HOST_12] in every future incident. That
enables cross-incident correlation ("this host appeared in 3 incidents this
week") that can even be shared with the AI — as placeholder statistics only,
never real values.

Storage: entity_vault.enc next to the app, encrypted with a Fernet key that
lives in the OS keychain (service "log_masker", entry "vault_key") — the same
keychain that already guards the provider API keys. The real values inside
never leave this machine, exactly like the per-conversation mappings.

The vault also records which incident (conversation) each entity appeared in,
plus the structured verdict the AI reached, so the UI can show an entity's
incident history and the prompt context can say "seen in 2 prior analyses,
verdicts: true_positive ×2".
"""

import json
import os
import re
from collections import Counter
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_FILE = os.path.join(_DIR, "entity_vault.enc")
KEYRING_SERVICE = "log_masker"
KEYRING_ENTRY = "vault_key"

_PH = re.compile(r"^\[([A-Z0-9]+)_(\d+)\]$")

# Test hooks: configure() points the vault at a throwaway file with a fixed
# key so tests never touch the real vault or the OS keychain.
_OVERRIDE = {"path": None, "key": None}

# Single-process app: the decrypted vault is cached here and written through
# on every mutation, so the auto-preview (which reads the mapping on every
# keystroke) never pays for a decrypt.
_CACHE: Optional[dict] = None
_FERNET = None
_WARNING = ""     # set when an unreadable vault file had to be set aside


def configure(path: str, key: Optional[str] = None) -> None:
    """Point the vault at `path` (tests / alternate profiles). Resets caches."""
    global _CACHE, _FERNET, _WARNING
    _OVERRIDE["path"] = path
    _OVERRIDE["key"] = key
    _CACHE = None
    _FERNET = None
    _WARNING = ""


def available() -> Tuple[bool, str]:
    """(usable, reason-if-not). The vault needs the cryptography package."""
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False, ("The entity vault needs the 'cryptography' package. "
                       "Run: pip install cryptography")
    return True, ""


def status_warning() -> str:
    """Non-fatal problem worth surfacing (e.g. an undecryptable vault file
    was set aside and a fresh vault started)."""
    return _WARNING


def _path() -> str:
    return _OVERRIDE["path"] or VAULT_FILE


def _fernet():
    global _FERNET
    if _FERNET is None:
        from cryptography.fernet import Fernet
        key = _OVERRIDE["key"]
        if not key:
            import keyring
            key = keyring.get_password(KEYRING_SERVICE, KEYRING_ENTRY)
            if not key:
                key = Fernet.generate_key().decode()
                keyring.set_password(KEYRING_SERVICE, KEYRING_ENTRY, key)
        _FERNET = Fernet(key.encode() if isinstance(key, str) else key)
    return _FERNET


def _empty() -> dict:
    return {"version": 1, "entities": {}, "incidents": {}, "counters": {}}


def _data() -> dict:
    global _CACHE, _WARNING
    if _CACHE is not None:
        return _CACHE
    path = _path()
    if not os.path.exists(path):
        _CACHE = _empty()
        return _CACHE
    try:
        with open(path, "rb") as f:
            blob = f.read()
        data = json.loads(_fernet().decrypt(blob))
        if not (isinstance(data, dict) and isinstance(data.get("entities"), dict)):
            raise ValueError("unexpected vault structure")
        data.setdefault("incidents", {})
        data.setdefault("counters", {})
        _CACHE = data
    except Exception:
        # Undecryptable or corrupt (e.g. the keychain entry was deleted).
        # Set the file aside rather than destroying it, and start fresh.
        backup = path + ".unreadable-" + datetime.now().strftime("%Y%m%d%H%M%S")
        try:
            os.replace(path, backup)
            _WARNING = (f"The vault file could not be decrypted; it was set "
                        f"aside as {os.path.basename(backup)} and a new vault "
                        f"was started.")
        except OSError:
            _WARNING = "The vault file could not be decrypted or replaced."
        _CACHE = _empty()
    return _CACHE


def _save(data: dict) -> None:
    global _CACHE
    _CACHE = data
    path = _path()
    blob = _fernet().encrypt(json.dumps(data, ensure_ascii=False).encode())
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
    os.replace(tmp, path)


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# The mapping the masker is seeded with
# ---------------------------------------------------------------------------
def mapping() -> Dict[str, str]:
    """placeholder -> real value for every vaulted entity. Passed to
    masker.mask() as base_mapping, so known values keep their placeholder
    and new placeholders continue the global numbering."""
    return {ph: e["value"] for ph, e in _data()["entities"].items()}


def counters() -> Dict[str, int]:
    """Per-label numbering high-water marks. Passed to masker.mask() as
    base_counters so a forgotten entity's number stays retired — the counters
    only ever count up, even when the entity itself is gone."""
    return dict(_data()["counters"])


# ---------------------------------------------------------------------------
# Recording incidents
# ---------------------------------------------------------------------------
def record(incident_id: str, entities: Dict[str, str],
           when: Optional[str] = None) -> int:
    """Upsert the entities {placeholder: real} seen in `incident_id`.
    Called after each analysis (and after follow-ups that introduce new
    values). Returns how many entities were new to the vault."""
    if not incident_id or not entities:
        return 0
    when = when or _now()
    data = _data()
    data["incidents"].setdefault(
        incident_id, {"time": when, "verdict": None, "severity": None})
    new = 0
    for ph, real in entities.items():
        m = _PH.match(ph)
        if not m or not real:
            continue
        label, n = m.group(1), int(m.group(2))
        data["counters"][label] = max(data["counters"].get(label, 0), n)
        e = data["entities"].get(ph)
        if e is None:
            data["entities"][ph] = {"label": m.group(1), "value": real,
                                    "first_seen": when, "last_seen": when,
                                    "incidents": [incident_id]}
            new += 1
        else:
            e["last_seen"] = when
            if incident_id not in e["incidents"]:
                e["incidents"].append(incident_id)
    _save(data)
    return new


def set_verdict(incident_id: str, verdict: Optional[str],
                severity: Optional[str]) -> None:
    """Attach the AI's structured verdict to an incident (updated when a
    follow-up changes the assessment)."""
    data = _data()
    inc = data["incidents"].get(incident_id)
    if not inc:
        return
    inc["verdict"] = verdict or inc.get("verdict")
    inc["severity"] = severity or inc.get("severity")
    _save(data)


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------
def entities() -> List[dict]:
    """Every vaulted entity with its incident history, for the UI."""
    data = _data()
    incs = data["incidents"]
    out = []
    for ph, e in data["entities"].items():
        m = _PH.match(ph)
        history = [{"id": iid,
                    "time": (incs.get(iid) or {}).get("time", ""),
                    "verdict": (incs.get(iid) or {}).get("verdict"),
                    "severity": (incs.get(iid) or {}).get("severity")}
                   for iid in e["incidents"]]
        out.append({"placeholder": ph,
                    "label": e["label"],
                    "n": int(m.group(2)) if m else 0,
                    "value": e["value"],
                    "first_seen": e["first_seen"],
                    "last_seen": e["last_seen"],
                    "incident_count": len(e["incidents"]),
                    "incidents": history})
    out.sort(key=lambda x: (-x["incident_count"], x["label"], x["n"]))
    return out


def stats() -> dict:
    data = _data()
    labels = Counter(e["label"] for e in data["entities"].values())
    return {"entities": len(data["entities"]),
            "incidents": len(data["incidents"]),
            "labels": dict(labels)}


def context_lines(placeholders: Iterable[str], limit: int = 8) -> List[str]:
    """Cross-incident history for the given placeholders, as lines that are
    safe to send to the AI: placeholder ids, counts, dates, and verdict
    labels only — NEVER real values. Only entities with at least one PRIOR
    incident are included (call this before record()ing the current one)."""
    data = _data()
    incs = data["incidents"]
    rows = []
    for ph in set(placeholders):
        e = data["entities"].get(ph)
        if not e or not e["incidents"]:
            continue
        verdicts = Counter()
        for iid in e["incidents"]:
            v = (incs.get(iid) or {}).get("verdict")
            if v:
                verdicts[v] += 1
        n = len(e["incidents"])
        line = (f"{ph}: seen in {n} prior "
                f"analys{'is' if n == 1 else 'es'} on this system "
                f"(first {e['first_seen'][:10]}, last {e['last_seen'][:10]}")
        if verdicts:
            line += "; verdicts: " + ", ".join(
                f"{v} ×{c}" for v, c in verdicts.most_common())
        line += ")"
        rows.append((n, ph, line))
    rows.sort(key=lambda r: (-r[0], r[1]))
    return [line for _, _, line in rows[:limit]]


# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------
def forget(placeholder: str) -> bool:
    """Remove one entity (wrong match, or data that must not persist).
    Its placeholder number is retired, not reused: numbering only ever
    counts up, so a future value can never inherit an old alias."""
    data = _data()
    if placeholder not in data["entities"]:
        return False
    del data["entities"][placeholder]
    _save(data)
    return True


def clear() -> None:
    """Wipe the vault (entities, incident history, and counters — numbering
    starts again from [TYPE_1])."""
    _save(_empty())
