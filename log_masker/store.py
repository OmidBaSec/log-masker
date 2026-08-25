"""
Local persistence for the user's custom always-mask terms and saved regex
patterns. A single global store (no multi-tenant separation) kept in
custom_store.json in the data directory (see paths.py).

On first run it migrates anything previously saved: custom patterns from the
legacy custom_patterns.json, and — if present — the terms/patterns of the old
default workspace from workspaces.json.
"""

import json
import os
from typing import Dict, List

from log_masker import paths

STORE_FILE = paths.data_file("custom_store.json")
LEGACY_PATTERNS_FILE = paths.data_file("custom_patterns.json")
LEGACY_WORKSPACES_FILE = paths.data_file("workspaces.json")


def _migrate() -> dict:
    terms: List[str] = []
    patterns: List[Dict[str, str]] = []
    # Old multi-tenant store: lift the default/active workspace if present.
    try:
        with open(LEGACY_WORKSPACES_FILE, encoding="utf-8") as f:
            data = json.load(f)
        wss = data.get("workspaces", {}) if isinstance(data, dict) else {}
        w = wss.get(data.get("active")) or wss.get("default") or \
            (next(iter(wss.values())) if wss else None)
        if isinstance(w, dict):
            terms = [t for t in w.get("custom_terms", []) if isinstance(t, str)]
            patterns = [p for p in w.get("custom_patterns", [])
                        if isinstance(p, dict) and p.get("regex") and p.get("label")]
    except (OSError, json.JSONDecodeError):
        pass
    # Legacy global patterns file.
    if not patterns:
        try:
            with open(LEGACY_PATTERNS_FILE, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                patterns = [p for p in data if isinstance(p, dict)
                            and p.get("regex") and p.get("label")]
        except (OSError, json.JSONDecodeError):
            pass
    return {"custom_terms": terms, "custom_patterns": patterns}


def _load() -> dict:
    try:
        with open(STORE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            data.setdefault("custom_terms", [])
            data.setdefault("custom_patterns", [])
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return _migrate()


def _save(data: dict) -> None:
    with open(STORE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# --- custom always-mask terms ----------------------------------------------
def get_terms() -> List[str]:
    return list(_load().get("custom_terms", []))


def set_terms(terms: List[str]) -> None:
    # Dedupe case-insensitively (terms are matched case-insensitively, so
    # "ACME" and "acme" are the same rule) while keeping the first-seen casing.
    data = _load()
    seen = set()
    out = []
    for t in terms:
        t = t.strip()
        if not t or t.lower() in seen:
            continue
        seen.add(t.lower())
        out.append(t)
    data["custom_terms"] = out
    _save(data)


# --- saved regex patterns ---------------------------------------------------
def get_patterns() -> List[Dict[str, str]]:
    return [p for p in _load().get("custom_patterns", [])
            if isinstance(p, dict) and p.get("regex") and p.get("label")]


def add_pattern(label: str, regex: str) -> None:
    data = _load()
    pats = data.setdefault("custom_patterns", [])
    if any(p.get("regex") == regex for p in pats):
        raise ValueError("This regex is already saved.")
    pats.append({"label": label, "regex": regex})
    _save(data)


def delete_pattern(index: int) -> None:
    data = _load()
    pats = data.get("custom_patterns", [])
    if not (0 <= index < len(pats)):
        raise ValueError("No such pattern.")
    pats.pop(index)
    _save(data)
