"""
Token/spend accounting for the credit dashboard.

Everything here is derived from the app's own append-only audit log
(ai_requests.jsonl) — the same file the Audit Trail view reads. Requests made
outside this app (another tool on the same key, a colleague's machine) are
invisible to it, which is why the UI always links out to the provider's billing
page for the authoritative number.

Two accuracy levels are tracked and reported separately:

  * exact     — token counts the provider returned with the response, captured
                by providers.call_with_usage() and stored on the log entry.
  * estimated — older entries (or providers that return no usage block), where
                tokens are inferred from the character count of what was sent
                and received.

The scan is incremental: the log only ever grows, so we remember the byte
offset we stopped at and the running per-bucket totals. Tokens are cached;
money is computed at read time, so editing a rate re-prices history instantly.
"""

import json
import os
from datetime import datetime
from typing import Dict, Optional

import pricing

APP_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(APP_DIR, "ai_requests.jsonl")

# buckets[provider][model][month] = {requests, in, out, estimated}
# conversations[id][model]         = the same, for one analyse + its follow-ups
_STATE: Dict[str, object] = {"offset": 0, "buckets": {}, "conversations": {}}


def _bucket(provider: str, model: str, month: str) -> dict:
    buckets = _STATE["buckets"]
    return (buckets
            .setdefault(provider or "unknown", {})
            .setdefault(model or "(unspecified)", {})
            .setdefault(month, {"requests": 0, "in": 0, "out": 0,
                                "estimated": 0}))


def _conv_bucket(conversation_id: str, provider: str, model: str) -> dict:
    conv = _STATE["conversations"].setdefault(
        conversation_id,
        {"provider": provider, "models": {}, "started": "", "last": ""})
    return conv["models"].setdefault(
        model or "(unspecified)",
        {"requests": 0, "in": 0, "out": 0, "estimated": 0})


def _entry_tokens(entry: dict):
    """(input_tokens, output_tokens, exact?) for one audit entry."""
    usage = entry.get("usage")
    if isinstance(usage, dict):
        try:
            return (int(usage.get("input_tokens") or 0),
                    int(usage.get("output_tokens") or 0), True)
        except (TypeError, ValueError):
            pass
    sent = entry.get("system") or ""
    for m in entry.get("messages") or []:
        sent += (m or {}).get("content") or ""
    return (pricing.estimate_tokens(sent),
            pricing.estimate_tokens(entry.get("response") or ""), False)


def _add(entry: dict) -> None:
    # A failed call was rejected before the model ran, so it costs nothing.
    if not entry.get("ok"):
        return
    month = (entry.get("time") or "")[:7] or datetime.now().strftime("%Y-%m")
    tokens_in, tokens_out, exact = _entry_tokens(entry)
    provider, model = entry.get("provider", ""), entry.get("model", "")
    for b in (_bucket(provider, model, month),
              _conv_bucket(entry["conversation_id"], provider, model)
              if entry.get("conversation_id") else None):
        if b is None:
            continue
        b["requests"] += 1
        b["in"] += tokens_in
        b["out"] += tokens_out
        if not exact:
            b["estimated"] += 1
    # First and last activity, so a finished conversation can report its span.
    cid = entry.get("conversation_id")
    if cid:
        conv = _STATE["conversations"][cid]
        when = entry.get("time") or ""
        conv["started"] = conv["started"] or when
        conv["last"] = when


def _scan() -> None:
    """Fold any log lines appended since the last call into the buckets."""
    try:
        size = os.path.getsize(LOG_FILE)
    except OSError:
        return
    # Truncated or replaced (e.g. the log was rotated) — start over.
    if size < _STATE["offset"]:
        _STATE["offset"] = 0
        _STATE["buckets"] = {}
    if size == _STATE["offset"]:
        return
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            f.seek(_STATE["offset"])
            for line in f:
                if not line.endswith("\n"):
                    # A partially written final line: stop before it and pick
                    # it up on the next scan.
                    break
                _STATE["offset"] += len(line.encode("utf-8"))
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict):
                    _add(entry)
    except OSError:
        return


def _sum_buckets(pairs, provider: str) -> dict:
    """Sum + price (model, bucket) pairs. Models we have no rate for are named
    in `unpriced` and contribute tokens but no cost."""
    out = {"requests": 0, "input_tokens": 0, "output_tokens": 0,
           "cost": 0.0, "estimated_requests": 0, "unpriced": []}
    rates = {}
    for model, b in pairs:
        if model not in rates:
            rates[model] = pricing.rate_for(provider, model)
        rate = rates[model]
        out["requests"] += b["requests"]
        out["input_tokens"] += b["in"]
        out["output_tokens"] += b["out"]
        out["estimated_requests"] += b["estimated"]
        out["cost"] += pricing.cost(rate, b["in"], b["out"])
        if rate is None and b["requests"] and model not in out["unpriced"]:
            out["unpriced"].append(model)
    return out


def _totals(models: dict, provider: str,
            only_month: Optional[str] = None) -> dict:
    """Sum + price one provider's buckets, optionally limited to one month
    ("YYYY-MM")."""
    def pairs():
        for model, months in models.items():
            for m, b in months.items():
                if only_month and m != only_month:
                    continue
                yield model, b
    return _sum_buckets(pairs(), provider)


def summary() -> dict:
    """Per-provider spend, month-to-date and all-time. Providers are keyed as
    in providers.PROVIDERS."""
    _scan()
    month = datetime.now().strftime("%Y-%m")
    out = {}
    for provider, models in _STATE["buckets"].items():
        out[provider] = {
            "month": _totals(models, provider, only_month=month),
            "all_time": _totals(models, provider),
        }
    return {"month": month, "currency": "USD", "providers": out,
            "log_file": LOG_FILE}


def conversation(conversation_id: str) -> Optional[dict]:
    """What one conversation cost: the opening analysis plus every follow-up
    logged under its id. Returns None for an id we have never seen."""
    _scan()
    conv = _STATE["conversations"].get(conversation_id)
    if not conv:
        return None
    totals = _sum_buckets(conv["models"].items(), conv["provider"])
    totals.update({
        "conversation_id": conversation_id,
        "provider": conv["provider"],
        "models": sorted(conv["models"].keys()),
        "started": conv["started"],
        "last": conv["last"],
        "currency": "USD",
    })
    return totals


def reset() -> None:
    """Forget the cached scan (used by tests and after the log is cleared)."""
    _STATE["offset"] = 0
    _STATE["buckets"] = {}
    _STATE["conversations"] = {}
