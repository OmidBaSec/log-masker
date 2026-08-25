"""
Token pricing for the credit dashboard.

None of the providers we support hands a plain API key a "remaining credit"
figure — balances live behind the billing consoles (and, for OpenAI/Anthropic,
behind org-admin keys that report *spend*, not what is left). So the dashboard
works the other way round: the app counts the tokens it spends and prices them
locally.

Rates are USD per 1M tokens and are deliberately editable. The seeded values
are published list prices for model *families* we recognise; they drift, they
ignore batch/cache discounts, and they never reflect negotiated or regional
(Azure) pricing. Anything unrecognised gets no rate at all — the dashboard
reports it as "rate not set" instead of quietly guessing.
"""

import json
import os
import re
from typing import Dict, Optional, Tuple

from log_masker import paths

RATES_FILE = paths.data_file("pricing.json")

# Characters per token when a request predates usage capture (or the provider
# returned no usage block). Deliberately crude — entries priced this way are
# flagged as estimated all the way through to the UI.
CHARS_PER_TOKEN = 4

# Ordered (regex, input $/1M, output $/1M). First match wins, so put the more
# specific families (mini/nano/lite) before their broader siblings.
DEFAULT_RATES: Tuple[Tuple[str, float, float], ...] = (
    # Anthropic
    (r"^claude.*opus",            15.00, 75.00),
    (r"^claude.*sonnet",           3.00, 15.00),
    (r"^claude.*haiku",            1.00,  5.00),
    # OpenAI
    (r"^(gpt|chatgpt).*nano",      0.05,  0.40),
    (r"^(gpt|chatgpt).*mini",      0.25,  2.00),
    (r"^(gpt|chatgpt)",            1.25, 10.00),
    (r"^o\d",                      1.10,  4.40),
    # Google
    (r"^gemini.*flash.*lite",      0.10,  0.40),
    (r"^gemini.*flash",            0.30,  2.50),
    (r"^gemini.*pro",              1.25, 10.00),
    # Local inference costs nothing per token.
    (r"^__ollama__$",              0.00,  0.00),
)

# Providers whose per-token price we can never guess: an Azure deployment name
# is arbitrary and its rate depends on the region and commitment, and M365
# Copilot is licensed per seat rather than billed per token.
_UNPRICEABLE = {"azure"}
_FREE_PROVIDERS = {"ollama"}
_LICENSED_PROVIDERS = {"m365copilot"}


def _load_overrides() -> Dict[str, dict]:
    """User-edited rates from pricing.json: {model_or_pattern: {in, out}}."""
    try:
        with open(RATES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    rates = data.get("rates") if isinstance(data, dict) else None
    return rates if isinstance(rates, dict) else {}


def _save_overrides(rates: Dict[str, dict]) -> None:
    with open(RATES_FILE, "w", encoding="utf-8") as f:
        json.dump({"rates": rates}, f, indent=2, sort_keys=True)


def set_rate(model: str, input_per_m: float, output_per_m: float) -> None:
    """Pin a rate for one model id, overriding any family default."""
    key = (model or "").strip().lower()
    if not key:
        raise ValueError("A model id is required.")
    if input_per_m < 0 or output_per_m < 0:
        raise ValueError("Rates cannot be negative.")
    rates = _load_overrides()
    rates[key] = {"in": float(input_per_m), "out": float(output_per_m)}
    _save_overrides(rates)


def clear_rate(model: str) -> None:
    """Drop a user override so the model falls back to its family default."""
    rates = _load_overrides()
    if rates.pop((model or "").strip().lower(), None) is not None:
        _save_overrides(rates)


def rate_for(provider: str, model: str) -> Optional[dict]:
    """The effective rate for a model, or None when we have no basis to price
    it. Returned as {"in": $/1M, "out": $/1M, "source": custom|default|free}."""
    if provider in _FREE_PROVIDERS:
        return {"in": 0.0, "out": 0.0, "source": "free"}
    if provider in _LICENSED_PROVIDERS:
        return {"in": 0.0, "out": 0.0, "source": "licensed"}

    key = (model or "").strip().lower()
    override = _load_overrides().get(key)
    if override:
        return {"in": float(override.get("in", 0.0)),
                "out": float(override.get("out", 0.0)),
                "source": "custom"}

    # An Azure deployment name says nothing about the underlying rate, so we
    # only price it once the analyst has entered one explicitly (above).
    if provider in _UNPRICEABLE or not key:
        return None

    for pattern, cost_in, cost_out in DEFAULT_RATES:
        if re.match(pattern, key):
            return {"in": cost_in, "out": cost_out, "source": "default"}
    return None


def estimate_tokens(text: str) -> int:
    """Rough token count for requests logged before usage capture existed."""
    if not text:
        return 0
    return max(1, len(text) // CHARS_PER_TOKEN)


def cost(rate: Optional[dict], input_tokens: int, output_tokens: int) -> float:
    """USD for a call. Unknown rate -> 0.0; callers flag those separately."""
    if not rate:
        return 0.0
    return (input_tokens / 1_000_000.0) * rate["in"] + \
           (output_tokens / 1_000_000.0) * rate["out"]


def table() -> list:
    """The effective rate table, for display in the UI."""
    overrides = _load_overrides()
    rows = [{"model": pattern, "in": cost_in, "out": cost_out,
             "source": "default", "pattern": True}
            for pattern, cost_in, cost_out in DEFAULT_RATES
            if not pattern.startswith("^__")]
    rows += [{"model": model, "in": float(r.get("in", 0.0)),
              "out": float(r.get("out", 0.0)), "source": "custom",
              "pattern": False}
             for model, r in sorted(overrides.items())]
    return rows
