"""
AI provider abstraction.

Each supported provider exposes the same interface: given a system prompt and a
(already-masked) user message, return the model's text response. Request and
response shapes differ per provider; this module hides those differences.

No masking happens here -- callers pass already-masked text. Keys are passed in
by the caller (resolved from the OS keychain), never read here.
"""

import re
import json
import requests
from typing import Dict, List, Optional

REQUEST_TIMEOUT = 120
MAX_TOKENS = 4096

# Local inference on modest hardware is much slower than a cloud API — give a
# local model plenty of time before declaring the request dead.
LOCAL_TIMEOUT = 600
OLLAMA_DEFAULT_ENDPOINT = "http://127.0.0.1:11434"


# ---------------------------------------------------------------------------
# Provider registry. `extra_fields` are non-secret settings the setup page must
# collect (e.g. Azure endpoint). `key_label` describes the API key to enter.
# ---------------------------------------------------------------------------
PROVIDERS: Dict[str, dict] = {
    "anthropic": {
        "label": "Claude (Anthropic)",
        "models": ["claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5"],
        "default_model": "claude-opus-4-8",
        "key_label": "Anthropic API key",
        "key_url": "https://console.anthropic.com/settings/keys",
        "billing_url": "https://console.anthropic.com/settings/billing",
        "extra_fields": [],
    },
    "openai": {
        "label": "ChatGPT (OpenAI)",
        "models": ["gpt-5.5", "gpt-5.5-pro", "gpt-5.4",
                   "gpt-5.4-mini", "gpt-5.4-nano"],
        "default_model": "gpt-5.5",
        "key_label": "OpenAI API key",
        "key_url": "https://platform.openai.com/api-keys",
        "billing_url": "https://platform.openai.com/settings/organization/billing/overview",
        "extra_fields": [],
    },
    "google": {
        "label": "Gemini (Google)",
        "models": ["gemini-3.5-flash", "gemini-3.1-pro-preview",
                   "gemini-3.1-flash-lite", "gemini-2.5-pro"],
        "default_model": "gemini-3.5-flash",
        "key_label": "Google AI Studio API key",
        "key_url": "https://aistudio.google.com/app/apikey",
        "billing_url": "https://aistudio.google.com/app/plan_information",
        "extra_fields": [],
    },
    "m365copilot": {
        "label": "Microsoft 365 Copilot",
        "models": [],          # no model choice; uses your tenant's Copilot
        "default_model": "",
        "auth": "oauth",        # sign-in flow, not an API key
        "key_label": "",
        "key_url": "https://entra.microsoft.com/",
        "billing_url": "https://admin.microsoft.com/Adminportal/Home#/subscriptions",
        "extra_fields": [
            {"key": "m365_tenant_id", "label": "Directory (tenant) ID",
             "placeholder": "00000000-0000-0000-0000-000000000000",
             "required": True},
            {"key": "m365_client_id", "label": "Application (client) ID",
             "placeholder": "00000000-0000-0000-0000-000000000000",
             "required": True},
        ],
        "note": ("Uses the Microsoft 365 Copilot Chat API (Microsoft Graph, "
                 "preview /beta). Requires a Copilot add-on license and an Entra "
                 "ID app registration. You sign in with Microsoft — no API key. "
                 "Answers are grounded in your tenant data."),
    },
    "ollama": {
        "label": "Local model (Ollama)",
        "models": [],           # live from the Ollama instance's /api/tags
        "default_model": "",
        "auth": "none",         # runs locally — no API key, no sign-in
        "key_label": "",
        "key_url": "https://ollama.com/download",
        "extra_fields": [
            {"key": "ollama_endpoint", "label": "Endpoint",
             "placeholder": OLLAMA_DEFAULT_ENDPOINT, "required": False},
        ],
        "note": ("Runs entirely on this machine via Ollama — for restricted "
                 "logs that must not reach any cloud provider, even masked. "
                 "Install Ollama, pull a model (e.g. `ollama pull llama3.1`), "
                 "and it appears in the model list. No API key; the endpoint "
                 "defaults to " + OLLAMA_DEFAULT_ENDPOINT + "."),
    },
    "azure": {
        "label": "Microsoft Copilot (Azure OpenAI)",
        "models": [],  # the deployment name acts as the model; user supplies it
        "default_model": "",
        "key_label": "Azure OpenAI API key",
        "key_url": "https://portal.azure.com/",
        "billing_url": "https://portal.azure.com/#view/Microsoft_Azure_GTM/ModernBillingMenuBlade",
        "extra_fields": [
            {"key": "azure_endpoint", "label": "Endpoint",
             "placeholder": "https://my-resource.openai.azure.com",
             "required": True},
            {"key": "azure_deployment", "label": "Deployment name",
             "placeholder": "my-gpt4o-deployment", "required": True},
            {"key": "azure_api_version", "label": "API version",
             "placeholder": "2024-08-01-preview", "required": True},
        ],
        "note": ("Microsoft has no public consumer-Copilot API. This uses the "
                 "Azure OpenAI Service, which backs Copilot. Create a resource "
                 "and a model deployment in the Azure portal."),
    },
}


class ProviderError(Exception):
    """Raised for configuration or upstream API errors."""


def _post(url: str, headers: dict, payload: dict,
          timeout: int = REQUEST_TIMEOUT) -> dict:
    resp = requests.post(url, headers=headers, data=json.dumps(payload),
                         timeout=timeout)
    if resp.status_code != 200:
        raise ProviderError(f"API error {resp.status_code}: {resp.text[:500]}")
    return resp.json()


def _usage(input_tokens, output_tokens) -> Optional[dict]:
    """Normalise a provider's usage block. None when it reported nothing, so
    callers can tell "no data" apart from a genuine zero."""
    if input_tokens is None and output_tokens is None:
        return None
    try:
        return {"input_tokens": int(input_tokens or 0),
                "output_tokens": int(output_tokens or 0),
                "source": "provider"}
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Per-provider callers. Each returns (response text, usage or None). Usage is
# what the provider itself billed for — the credit dashboard prefers it over
# character-based estimates.
# ---------------------------------------------------------------------------
# Each caller receives `messages`: a list of {"role": "user"|"assistant",
# "content": str} covering the whole (masked) conversation so far, so models
# keep the context of earlier turns.
def _call_anthropic(api_key, model, system, messages, cfg) -> str:
    data = _post(
        "https://api.anthropic.com/v1/messages",
        {"x-api-key": api_key, "anthropic-version": "2023-06-01",
         "content-type": "application/json"},
        {"model": model, "max_tokens": MAX_TOKENS, "system": system,
         "messages": messages},
    )
    u = data.get("usage") or {}
    return ("".join(b.get("text", "") for b in data.get("content", [])
                    if b.get("type") == "text").strip(),
            _usage(u.get("input_tokens"), u.get("output_tokens")))


def _call_openai(api_key, model, system, messages, cfg) -> str:
    data = _post(
        "https://api.openai.com/v1/chat/completions",
        {"Authorization": f"Bearer {api_key}",
         "content-type": "application/json"},
        {"model": model,
         "messages": [{"role": "system", "content": system}] + messages},
    )
    return _chat_completion_result(data)


def _chat_completion_result(data: dict):
    """OpenAI-compatible response shape, shared by OpenAI and Azure OpenAI."""
    u = data.get("usage") or {}
    return (data["choices"][0]["message"]["content"].strip(),
            _usage(u.get("prompt_tokens"), u.get("completion_tokens")))


def _call_google(api_key, model, system, messages, cfg) -> str:
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model}:generateContent?key={api_key}")
    contents = [{"role": "user" if m["role"] == "user" else "model",
                 "parts": [{"text": m["content"]}]} for m in messages]
    data = _post(
        url, {"content-type": "application/json"},
        {"system_instruction": {"parts": [{"text": system}]},
         "contents": contents},
    )
    cand = data.get("candidates", [])
    if not cand:
        raise ProviderError(f"No response from Gemini: {json.dumps(data)[:400]}")
    parts = cand[0].get("content", {}).get("parts", [])
    u = data.get("usageMetadata") or {}
    return ("".join(p.get("text", "") for p in parts).strip(),
            _usage(u.get("promptTokenCount"), u.get("candidatesTokenCount")))


def _call_azure(api_key, model, system, messages, cfg) -> str:
    endpoint = (cfg.get("azure_endpoint") or "").rstrip("/")
    deployment = cfg.get("azure_deployment") or model
    api_version = cfg.get("azure_api_version") or "2024-08-01-preview"
    if not endpoint or not deployment:
        raise ProviderError("Azure endpoint and deployment name are required.")
    url = (f"{endpoint}/openai/deployments/{deployment}/chat/completions"
           f"?api-version={api_version}")
    data = _post(
        url, {"api-key": api_key, "content-type": "application/json"},
        {"messages": [{"role": "system", "content": system}] + messages},
    )
    return _chat_completion_result(data)


def _ollama_endpoint(cfg) -> str:
    return ((cfg or {}).get("ollama_endpoint")
            or OLLAMA_DEFAULT_ENDPOINT).rstrip("/")


def _call_ollama(api_key, model, system, messages, cfg) -> str:
    """Local inference via Ollama's native chat API. No key: the model runs on
    this machine, so even the masked text never leaves it."""
    if not model:
        raise ProviderError("Choose a local model first (e.g. llama3.1 — "
                            "pull one with `ollama pull llama3.1`).")
    endpoint = _ollama_endpoint(cfg)
    msgs = ([{"role": "system", "content": system}] if system else []) + messages
    try:
        data = _post(f"{endpoint}/api/chat",
                     {"content-type": "application/json"},
                     {"model": model, "messages": msgs, "stream": False,
                      "options": {"num_predict": MAX_TOKENS}},
                     timeout=LOCAL_TIMEOUT)
    except requests.exceptions.ConnectionError:
        raise ProviderError(f"Could not reach Ollama at {endpoint} — is it "
                            f"running? (`ollama serve`, or open the Ollama app)")
    # Local inference is free, but the counts still drive the usage view.
    return ((data.get("message") or {}).get("content", "").strip(),
            _usage(data.get("prompt_eval_count"), data.get("eval_count")))


_CALLERS = {
    "anthropic": _call_anthropic,
    "openai": _call_openai,
    "google": _call_google,
    "azure": _call_azure,
    "ollama": _call_ollama,
}


def call_with_usage(provider: str, api_key: str, model: str, system: str,
                    messages, cfg: Optional[dict] = None):
    """Send a conversation to `provider`; returns (response text, usage).
    `usage` is {input_tokens, output_tokens, source} as reported by the
    provider, or None when it reported nothing.
    `messages` is a list of {"role": "user"|"assistant", "content": str};
    a plain string is accepted as a single-turn convenience."""
    if isinstance(messages, str):
        messages = [{"role": "user", "content": messages}]
    if provider not in _CALLERS:
        raise ProviderError(f"Unknown provider: {provider}")
    if not api_key and needs_key(provider):
        raise ProviderError("No API key configured for this provider.")
    return _CALLERS[provider](api_key, model, system, messages, cfg or {})


def call(provider: str, api_key: str, model: str, system: str,
         messages, cfg: Optional[dict] = None,
         usage_out: Optional[dict] = None) -> str:
    """Response text. Pass a dict as `usage_out` to also receive the token
    counts the provider billed for — an out-parameter rather than a second
    return value so this stays the one entry point every caller (and every
    test stub) already talks to."""
    text, usage = call_with_usage(provider, api_key, model, system,
                                  messages, cfg)
    if usage_out is not None and usage:
        usage_out.update(usage)
    return text


def needs_key(provider: str) -> bool:
    """False for providers that authenticate some other way (OAuth) or not at
    all (a local model)."""
    return PROVIDERS.get(provider, {}).get("auth", "apikey") == "apikey"


def reachable(provider: str, cfg: Optional[dict] = None) -> bool:
    """Quick liveness probe for local/keyless providers, used for the setup
    page's status dot. Short timeout: a local endpoint answers instantly."""
    if provider != "ollama":
        return False
    try:
        r = requests.get(f"{_ollama_endpoint(cfg)}/api/version", timeout=2)
        return r.status_code == 200
    except requests.RequestException:
        return False


# ---------------------------------------------------------------------------
# Live model listing — query each provider's catalog so the dropdown never goes
# stale. Best-effort filtering to chat/text models.
# ---------------------------------------------------------------------------
_OPENAI_EXCLUDE = ("audio", "realtime", "transcribe", "tts", "image",
                   "embedding", "search", "moderation", "dall", "whisper")
_GOOGLE_EXCLUDE = ("image", "tts", "embedding", "aqa", "vision", "live",
                   "computer-use", "robotics", "nano-banana", "lyria",
                   "deep-research")


def _get(url: str, headers: dict = None) -> dict:
    r = requests.get(url, headers=headers or {}, timeout=30)
    if r.status_code != 200:
        raise ProviderError(f"List models failed {r.status_code}: {r.text[:300]}")
    return r.json()


def list_models(provider: str, api_key: str, cfg: Optional[dict] = None) -> List[str]:
    """Return chat/text model IDs currently available for `provider`'s key."""
    if provider == "ollama":
        endpoint = _ollama_endpoint(cfg)
        try:
            data = _get(f"{endpoint}/api/tags")
        except requests.exceptions.ConnectionError:
            raise ProviderError(f"Could not reach Ollama at {endpoint} — is it "
                                f"running? (`ollama serve`)")
        return sorted(m.get("name", "") for m in data.get("models", [])
                      if m.get("name"))

    if provider == "anthropic":
        data = _get("https://api.anthropic.com/v1/models",
                    {"x-api-key": api_key, "anthropic-version": "2023-06-01"})
        return [m["id"] for m in data.get("data", [])]

    if provider == "openai":
        data = _get("https://api.openai.com/v1/models",
                    {"Authorization": f"Bearer {api_key}"})
        out = []
        for m in data.get("data", []):
            mid = m.get("id", "")
            low = mid.lower()
            if any(x in low for x in _OPENAI_EXCLUDE):
                continue
            if low.startswith(("gpt", "chatgpt")) or re.match(r"^o\d", low):
                out.append(mid)
        return sorted(set(out))

    if provider == "google":
        data = _get("https://generativelanguage.googleapis.com/v1beta/models"
                    f"?key={api_key}&pageSize=200")
        out = []
        for m in data.get("models", []):
            if "generateContent" not in (m.get("supportedGenerationMethods") or []):
                continue
            name = m.get("name", "").replace("models/", "")
            low = name.lower()
            if any(x in low for x in _GOOGLE_EXCLUDE):
                continue
            if low.startswith(("gemini", "gemma")):
                out.append(name)
        return out

    # azure (deployment-based) and m365copilot have no listable chat catalog here.
    return []


def public_registry() -> dict:
    """Provider metadata safe to expose to the frontend (no secrets)."""
    out = {}
    for pid, meta in PROVIDERS.items():
        out[pid] = {
            "label": meta["label"],
            "models": meta["models"],
            "default_model": meta["default_model"],
            "auth": meta.get("auth", "apikey"),
            "key_label": meta["key_label"],
            "key_url": meta["key_url"],
            "billing_url": meta.get("billing_url", ""),
            "extra_fields": meta["extra_fields"],
            "note": meta.get("note", ""),
        }
    return out
