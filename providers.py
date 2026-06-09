"""
AI provider abstraction.

Each supported provider exposes the same interface: given a system prompt and a
(already-masked) user message, return the model's text response. Request and
response shapes differ per provider; this module hides those differences.

No masking happens here -- callers pass already-masked text. Keys are passed in
by the caller (resolved from the OS keychain), never read here.
"""

import json
import requests
from typing import Dict, List, Optional

REQUEST_TIMEOUT = 120
MAX_TOKENS = 4096


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
        "extra_fields": [],
    },
    "openai": {
        "label": "ChatGPT (OpenAI)",
        "models": ["gpt-5.5", "gpt-5.5-pro", "gpt-5.4",
                   "gpt-5.4-mini", "gpt-5.4-nano"],
        "default_model": "gpt-5.5",
        "key_label": "OpenAI API key",
        "key_url": "https://platform.openai.com/api-keys",
        "extra_fields": [],
    },
    "google": {
        "label": "Gemini (Google)",
        "models": ["gemini-3.5-flash", "gemini-3.1-pro-preview",
                   "gemini-3.1-flash-lite", "gemini-2.5-pro"],
        "default_model": "gemini-3.5-flash",
        "key_label": "Google AI Studio API key",
        "key_url": "https://aistudio.google.com/app/apikey",
        "extra_fields": [],
    },
    "m365copilot": {
        "label": "Microsoft 365 Copilot",
        "models": [],          # no model choice; uses your tenant's Copilot
        "default_model": "",
        "auth": "oauth",        # sign-in flow, not an API key
        "key_label": "",
        "key_url": "https://entra.microsoft.com/",
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
    "azure": {
        "label": "Microsoft Copilot (Azure OpenAI)",
        "models": [],  # the deployment name acts as the model; user supplies it
        "default_model": "",
        "key_label": "Azure OpenAI API key",
        "key_url": "https://portal.azure.com/",
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


def _post(url: str, headers: dict, payload: dict) -> dict:
    resp = requests.post(url, headers=headers, data=json.dumps(payload),
                         timeout=REQUEST_TIMEOUT)
    if resp.status_code != 200:
        raise ProviderError(f"API error {resp.status_code}: {resp.text[:500]}")
    return resp.json()


# ---------------------------------------------------------------------------
# Per-provider callers. Each returns the response text.
# ---------------------------------------------------------------------------
def _call_anthropic(api_key, model, system, user_text, cfg) -> str:
    data = _post(
        "https://api.anthropic.com/v1/messages",
        {"x-api-key": api_key, "anthropic-version": "2023-06-01",
         "content-type": "application/json"},
        {"model": model, "max_tokens": MAX_TOKENS, "system": system,
         "messages": [{"role": "user", "content": user_text}]},
    )
    return "".join(b.get("text", "") for b in data.get("content", [])
                   if b.get("type") == "text").strip()


def _call_openai(api_key, model, system, user_text, cfg) -> str:
    data = _post(
        "https://api.openai.com/v1/chat/completions",
        {"Authorization": f"Bearer {api_key}",
         "content-type": "application/json"},
        {"model": model, "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_text}]},
    )
    return data["choices"][0]["message"]["content"].strip()


def _call_google(api_key, model, system, user_text, cfg) -> str:
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model}:generateContent?key={api_key}")
    data = _post(
        url, {"content-type": "application/json"},
        {"system_instruction": {"parts": [{"text": system}]},
         "contents": [{"role": "user", "parts": [{"text": user_text}]}]},
    )
    cand = data.get("candidates", [])
    if not cand:
        raise ProviderError(f"No response from Gemini: {json.dumps(data)[:400]}")
    parts = cand[0].get("content", {}).get("parts", [])
    return "".join(p.get("text", "") for p in parts).strip()


def _call_azure(api_key, model, system, user_text, cfg) -> str:
    endpoint = (cfg.get("azure_endpoint") or "").rstrip("/")
    deployment = cfg.get("azure_deployment") or model
    api_version = cfg.get("azure_api_version") or "2024-08-01-preview"
    if not endpoint or not deployment:
        raise ProviderError("Azure endpoint and deployment name are required.")
    url = (f"{endpoint}/openai/deployments/{deployment}/chat/completions"
           f"?api-version={api_version}")
    data = _post(
        url, {"api-key": api_key, "content-type": "application/json"},
        {"messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_text}]},
    )
    return data["choices"][0]["message"]["content"].strip()


_CALLERS = {
    "anthropic": _call_anthropic,
    "openai": _call_openai,
    "google": _call_google,
    "azure": _call_azure,
}


def call(provider: str, api_key: str, model: str, system: str,
         user_text: str, cfg: Optional[dict] = None) -> str:
    """Send a request to `provider` and return the response text."""
    if provider not in _CALLERS:
        raise ProviderError(f"Unknown provider: {provider}")
    if not api_key:
        raise ProviderError("No API key configured for this provider.")
    return _CALLERS[provider](api_key, model, system, user_text, cfg or {})


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
            "extra_fields": meta["extra_fields"],
            "note": meta.get("note", ""),
        }
    return out
