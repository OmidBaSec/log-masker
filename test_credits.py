"""Checks for the credit dashboard: pricing rules, usage accounting, and the
token counts providers report back. Run: python test_credits.py

Nothing here touches the network or the real audit log — the log path is
pointed at a temp file and provider HTTP calls are stubbed.
"""

import json
import os
import tempfile

from log_masker import pricing
from log_masker import providers
from log_masker import usage


def check(name, cond):
    print(("PASS" if cond else "FAIL") + " - " + name)
    assert cond, name


class FakeResp:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status
        self.text = json.dumps(data)

    def json(self):
        return self._data


# ---------------------------------------------------------------------------
# Pricing
# ---------------------------------------------------------------------------
def test_rates():
    opus = pricing.rate_for("anthropic", "claude-opus-5")
    check("model families match a seeded rate", opus and opus["source"] == "default")
    mini = pricing.rate_for("openai", "gpt-5.4-mini")
    full = pricing.rate_for("openai", "gpt-5.5")
    check("the more specific family wins", mini["in"] < full["in"])
    check("local inference is free",
          pricing.rate_for("ollama", "llama3.1")["source"] == "free")
    check("a seat licence is not billed per token",
          pricing.rate_for("m365copilot", "")["source"] == "licensed")
    check("an unknown model has no rate rather than a guessed one",
          pricing.rate_for("anthropic", "some-unreleased-model") is None)
    check("an azure deployment name is never guessed at",
          pricing.rate_for("azure", "my-deployment") is None)


def test_rate_overrides():
    real_file = pricing.RATES_FILE
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.unlink(path)
    pricing.RATES_FILE = path
    try:
        pricing.set_rate("my-deployment", 2.0, 8.0)
        rate = pricing.rate_for("azure", "MY-Deployment")
        check("an override prices an otherwise unpriceable model",
              rate and rate["source"] == "custom" and rate["in"] == 2.0)
        check("override lookup is case-insensitive", rate["out"] == 8.0)
        pricing.set_rate("claude-opus-5", 1.0, 2.0)
        check("an override beats the family default",
              pricing.rate_for("anthropic", "claude-opus-5")["in"] == 1.0)
        pricing.clear_rate("claude-opus-5")
        check("clearing falls back to the family default",
              pricing.rate_for("anthropic", "claude-opus-5")["source"] == "default")
        try:
            pricing.set_rate("x", -1, 1)
            negative_rejected = False
        except ValueError:
            negative_rejected = True
        check("negative rates are rejected", negative_rejected)
    finally:
        if os.path.exists(path):
            os.unlink(path)
        pricing.RATES_FILE = real_file


def test_cost():
    rate = {"in": 3.0, "out": 15.0}
    check("cost is per 1M tokens",
          abs(pricing.cost(rate, 1_000_000, 1_000_000) - 18.0) < 1e-9)
    check("no rate means no cost claimed", pricing.cost(None, 999999, 999999) == 0.0)


# ---------------------------------------------------------------------------
# Usage accounting
# ---------------------------------------------------------------------------
def _entry(**kw):
    e = {"time": "2026-08-02 10:00:00", "provider": "anthropic",
         "model": "claude-opus-5", "system": "", "messages": [],
         "response": "", "ok": True}
    e.update(kw)
    return e


def _with_log(entries):
    """Run usage.summary() over a temp log holding `entries`."""
    real_file = usage.LOG_FILE
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    usage.LOG_FILE = path
    usage.reset()
    try:
        return usage.summary()
    finally:
        os.unlink(path)
        usage.LOG_FILE = real_file
        usage.reset()


def test_usage_totals():
    s = _with_log([
        _entry(usage={"input_tokens": 1_000_000, "output_tokens": 100_000}),
        _entry(usage={"input_tokens": 500_000, "output_tokens": 0}),
    ])
    a = s["providers"]["anthropic"]
    check("provider token counts are summed",
          a["all_time"]["input_tokens"] == 1_500_000)
    # 1.5M in @ $15 + 100k out @ $75 = $22.50 + $7.50
    check("tokens are priced with the model's rate",
          abs(a["all_time"]["cost"] - 30.0) < 1e-6)
    check("exact counts are not flagged as estimated",
          a["all_time"]["estimated_requests"] == 0)


def test_failed_calls_are_free():
    s = _with_log([
        _entry(ok=False, error="401", usage={"input_tokens": 999, "output_tokens": 9}),
        _entry(usage={"input_tokens": 1000, "output_tokens": 0}),
    ])
    a = s["providers"]["anthropic"]
    check("a rejected call is not counted", a["all_time"]["requests"] == 1)
    check("only the successful call's tokens land",
          a["all_time"]["input_tokens"] == 1000)


def test_estimates_are_flagged():
    s = _with_log([_entry(messages=[{"role": "user", "content": "x" * 4000}],
                          response="y" * 400)])
    a = s["providers"]["anthropic"]
    check("entries without a usage block still count tokens",
          a["all_time"]["input_tokens"] == 1000)
    check("...and are reported as estimated",
          a["all_time"]["estimated_requests"] == 1)


def test_unpriced_models_surface():
    s = _with_log([_entry(model="brand-new-model",
                          usage={"input_tokens": 1000, "output_tokens": 1000})])
    a = s["providers"]["anthropic"]
    check("an unpriced model is named rather than costed",
          a["all_time"]["unpriced"] == ["brand-new-model"])
    check("its cost is not invented", a["all_time"]["cost"] == 0.0)
    check("its tokens are still counted", a["all_time"]["input_tokens"] == 1000)


def test_incremental_scan():
    real_file = usage.LOG_FILE
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    usage.LOG_FILE = path
    usage.reset()
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(
                _entry(usage={"input_tokens": 100, "output_tokens": 0})) + "\n")
        first = usage.summary()["providers"]["anthropic"]["all_time"]
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(
                _entry(usage={"input_tokens": 400, "output_tokens": 0})) + "\n")
        second = usage.summary()["providers"]["anthropic"]["all_time"]
        check("a re-scan picks up appended lines", second["input_tokens"] == 500)
        check("...without double-counting the old ones",
              first["input_tokens"] == 100 and second["requests"] == 2)
    finally:
        os.unlink(path)
        usage.LOG_FILE = real_file
        usage.reset()


def test_conversation_cost():
    entries = [
        _entry(time="2026-08-02 10:00:00", conversation_id="abc",
               usage={"input_tokens": 1_000_000, "output_tokens": 0}),   # $15
        _entry(time="2026-08-02 10:05:00", conversation_id="abc",
               usage={"input_tokens": 0, "output_tokens": 100_000}),     # $7.50
        _entry(time="2026-08-02 10:06:00", conversation_id="other",
               usage={"input_tokens": 1_000_000, "output_tokens": 0}),
        # A connection test has no conversation of its own.
        _entry(time="2026-08-02 10:07:00", conversation_id=None, kind="test",
               usage={"input_tokens": 1_000_000, "output_tokens": 0}),
    ]
    real_file = usage.LOG_FILE
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    usage.LOG_FILE = path
    usage.reset()
    try:
        c = usage.conversation("abc")
        check("a conversation sums its analysis and follow-ups",
              c["requests"] == 2)
        check("...and only its own calls",
              abs(c["cost"] - 22.5) < 1e-6)
        check("it reports the span it ran over",
              c["started"] == "2026-08-02 10:00:00"
              and c["last"] == "2026-08-02 10:05:00")
        check("the model is named", c["models"] == ["claude-opus-5"])
        check("an unknown conversation id returns nothing",
              usage.conversation("never-existed") is None)
        check("per-provider totals still see every call",
              usage.summary()["providers"]["anthropic"]["all_time"]["requests"] == 4)
    finally:
        os.unlink(path)
        usage.LOG_FILE = real_file
        usage.reset()


def test_conversation_unpriced():
    real_file = usage.LOG_FILE
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(_entry(conversation_id="x", model="brand-new-model",
                                  usage={"input_tokens": 2000,
                                         "output_tokens": 500})) + "\n")
    usage.LOG_FILE = path
    usage.reset()
    try:
        c = usage.conversation("x")
        check("a conversation on an unpriced model names the model",
              c["unpriced"] == ["brand-new-model"])
        check("...is not costed", c["cost"] == 0.0)
        check("...but its tokens are still counted",
              c["input_tokens"] == 2000 and c["output_tokens"] == 500)
    finally:
        os.unlink(path)
        usage.LOG_FILE = real_file
        usage.reset()


# ---------------------------------------------------------------------------
# Usage capture from provider responses
# ---------------------------------------------------------------------------
def test_provider_usage_capture():
    cases = {
        "anthropic": ({"content": [{"type": "text", "text": "hi"}],
                       "usage": {"input_tokens": 11, "output_tokens": 22}}, 11, 22),
        "openai": ({"choices": [{"message": {"content": "hi"}}],
                    "usage": {"prompt_tokens": 33, "completion_tokens": 44}}, 33, 44),
        "google": ({"candidates": [{"content": {"parts": [{"text": "hi"}]}}],
                    "usageMetadata": {"promptTokenCount": 55,
                                      "candidatesTokenCount": 66}}, 55, 66),
        "ollama": ({"message": {"content": "hi"}, "prompt_eval_count": 77,
                    "eval_count": 88}, 77, 88),
    }
    real_post = providers.requests.post
    try:
        for provider, (payload, want_in, want_out) in cases.items():
            providers.requests.post = (
                lambda url, headers=None, data=None, timeout=None, _p=payload:
                FakeResp(_p))
            text, u = providers.call_with_usage(
                provider, "key", "model", "sys",
                [{"role": "user", "content": "q"}], {})
            check(f"{provider}: response text still returned", text == "hi")
            check(f"{provider}: token counts captured",
                  u["input_tokens"] == want_in and u["output_tokens"] == want_out)
            check(f"{provider}: counts are marked as the provider's own",
                  u["source"] == "provider")

        # A provider that reports nothing must not fake a zero-token call.
        providers.requests.post = (
            lambda url, headers=None, data=None, timeout=None:
            FakeResp({"content": [{"type": "text", "text": "hi"}]}))
        _, u = providers.call_with_usage("anthropic", "key", "m", "s", "q", {})
        check("a missing usage block yields no usage", u is None)

        # The plain call() form keeps working for callers that don't care.
        out = {}
        providers.requests.post = (
            lambda url, headers=None, data=None, timeout=None:
            FakeResp({"content": [{"type": "text", "text": "hi"}],
                      "usage": {"input_tokens": 5, "output_tokens": 6}}))
        text = providers.call("anthropic", "key", "m", "s", "q", {},
                              usage_out=out)
        check("call() returns just the text", text == "hi")
        check("call() fills usage_out when asked", out["input_tokens"] == 5)
    finally:
        providers.requests.post = real_post


if __name__ == "__main__":
    test_rates()
    test_rate_overrides()
    test_cost()
    test_usage_totals()
    test_failed_calls_are_free()
    test_estimates_are_flagged()
    test_unpriced_models_surface()
    test_incremental_scan()
    test_conversation_cost()
    test_conversation_unpriced()
    test_provider_usage_capture()
    print("\nAll credit tests passed.")
