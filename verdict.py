"""
Structured verdict support.

When structured mode is on, the system prompt asks the model to end its answer
with a fenced ```json block following a fixed schema (verdict / confidence /
severity / MITRE / IOCs / actions...). This module builds that instruction and
parses the block back out of the (still-masked) response, so the app can render
a consistent verdict card and export machine-readable JSON for XSOAR/records.

Parsing happens on the MASKED text; placeholders like [IP_1] are JSON-safe, so
the caller parses first and then restores real values into the structured
object — never the other way round (a restored value could contain a quote and
break the JSON).
"""

import json
import re
from typing import Optional, Tuple

# The ordered fields of a verdict, with their allowed/expected shapes. Kept here
# so the UI and any consumer share one contract.
VERDICT_FIELDS = (
    "verdict", "confidence", "severity", "summary",
    "mitre", "iocs", "affected_entities", "recommended_actions", "next_steps",
)

VERDICT_VALUES = ("true_positive", "false_positive",
                  "benign_true_positive", "inconclusive")
CONFIDENCE_VALUES = ("high", "medium", "low")
SEVERITY_VALUES = ("critical", "high", "medium", "low", "informational")


SCHEMA_PROMPT = (
    "\n\nAFTER your prose analysis, output a SOC verdict as a single fenced "
    "```json code block, and nothing after it. Use exactly this structure:\n"
    "```json\n"
    "{\n"
    '  "verdict": "true_positive | false_positive | benign_true_positive | inconclusive",\n'
    '  "confidence": "high | medium | low",\n'
    '  "severity": "critical | high | medium | low | informational",\n'
    '  "summary": "one sentence stating the verdict and why",\n'
    '  "mitre": [{"tactic": "", "technique": "", "technique_id": "T...."}],\n'
    '  "iocs": [{"type": "ip|domain|host|user|hash|url|email|other", "value": "", "context": ""}],\n'
    '  "affected_entities": [""],\n'
    '  "recommended_actions": [""],\n'
    '  "next_steps": [""]\n'
    "}\n"
    "```\n"
    "Rules: keep the bracketed placeholders verbatim in any value (e.g. [IP_1], "
    "[USER_2]) — never invent real values. Use empty arrays where nothing "
    "applies. Output valid JSON only inside the block. Choose 'inconclusive' if "
    "the evidence is insufficient rather than guessing."
)

_FENCED = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)


def _coerce_list(v) -> list:
    if isinstance(v, list):
        return v
    if v in (None, "", []):
        return []
    return [v]


def _normalize(obj: dict) -> dict:
    """Coerce a parsed object into the canonical verdict shape so the UI can
    rely on every field existing with the right type."""
    out = {
        "verdict": str(obj.get("verdict", "inconclusive")).strip().lower()
                   .replace(" ", "_").replace("-", "_"),
        "confidence": str(obj.get("confidence", "")).strip().lower(),
        "severity": str(obj.get("severity", "")).strip().lower(),
        "summary": str(obj.get("summary", "")).strip(),
        "mitre": [],
        "iocs": [],
        "affected_entities": [str(x).strip() for x in
                              _coerce_list(obj.get("affected_entities")) if str(x).strip()],
        "recommended_actions": [str(x).strip() for x in
                                _coerce_list(obj.get("recommended_actions")) if str(x).strip()],
        "next_steps": [str(x).strip() for x in
                       _coerce_list(obj.get("next_steps")) if str(x).strip()],
    }
    if out["verdict"] not in VERDICT_VALUES:
        out["verdict"] = "inconclusive"
    if out["confidence"] not in CONFIDENCE_VALUES:
        out["confidence"] = ""
    if out["severity"] not in SEVERITY_VALUES:
        out["severity"] = ""
    for m in _coerce_list(obj.get("mitre")):
        if isinstance(m, dict):
            out["mitre"].append({
                "tactic": str(m.get("tactic", "")).strip(),
                "technique": str(m.get("technique", "")).strip(),
                "technique_id": str(m.get("technique_id", "")).strip(),
            })
        elif str(m).strip():
            out["mitre"].append({"tactic": "", "technique": str(m).strip(),
                                 "technique_id": ""})
    for it in _coerce_list(obj.get("iocs")):
        if isinstance(it, dict):
            val = str(it.get("value", "")).strip()
            if not val:
                continue
            out["iocs"].append({
                "type": str(it.get("type", "other")).strip().lower() or "other",
                "value": val,
                "context": str(it.get("context", "")).strip(),
            })
        elif str(it).strip():
            out["iocs"].append({"type": "other", "value": str(it).strip(),
                               "context": ""})
    return out


def split_response(text: str) -> Tuple[str, Optional[dict]]:
    """Return (prose_without_verdict_block, verdict_dict_or_None).

    Operates on the masked response. The verdict object still contains
    placeholders; the caller restores them afterwards.
    """
    if not text:
        return text, None
    candidates = list(_FENCED.finditer(text))
    for m in reversed(candidates):           # last block wins
        try:
            obj = json.loads(m.group(1))
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict) and "verdict" in obj:
            prose = (text[:m.start()] + text[m.end():]).strip()
            return prose, _normalize(obj)
    # No fenced block — tolerate a bare top-level JSON object with a verdict.
    stripped = text.strip()
    if stripped.startswith("{") and '"verdict"' in stripped:
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict) and "verdict" in obj:
                return "", _normalize(obj)
        except (json.JSONDecodeError, ValueError):
            pass
    return text, None


def restore(obj, unmask, mapping):
    """Recursively replace placeholders with real values in a parsed verdict,
    using the caller's unmask(text, mapping) function on every string leaf."""
    if isinstance(obj, dict):
        return {k: restore(v, unmask, mapping) for k, v in obj.items()}
    if isinstance(obj, list):
        return [restore(v, unmask, mapping) for v in obj]
    if isinstance(obj, str):
        return unmask(obj, mapping)
    return obj
