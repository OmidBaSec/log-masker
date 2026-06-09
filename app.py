"""
Log Masker -- a local web app that scrubs sensitive data from raw logs before
sending them to a public AI provider for security analysis, then restores the
real values in the response.

Flow:
  1. You paste raw logs in the browser and pick which data types to mask.
  2. The server masks them LOCALLY (see masker.py) -- only placeholders leave
     this machine.
  3. The masked text is sent to the configured AI provider (Claude / ChatGPT /
     Gemini / Azure OpenAI -- see providers.py) for analysis.
  4. The masked placeholders in the response are replaced back with the real
     values, locally, and shown to you.

The mask -> real mapping never leaves the server process. API keys live in the
OS keychain (via keyring); non-secret settings live in app_config.json.
"""

import os
import sys
import json
import keyring
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import masker
import providers
import m365

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
APP_DIR = os.path.dirname(__file__)
STATIC_DIR = os.path.join(APP_DIR, "static")
CONFIG_FILE = os.path.join(APP_DIR, "app_config.json")
KEYRING_SERVICE = "log_masker"

# Non-secret settings persisted to CONFIG_FILE.
#   provider         -> the DEFAULT provider used for analysis
#   provider_models  -> the DEFAULT model chosen for EACH provider
DEFAULT_CONFIG = {
    "provider": "anthropic",
    "provider_models": {
        "anthropic": "claude-opus-4-8",
        "openai": "gpt-5.5",
        "google": "gemini-3.5-flash",
        "azure": "",
        "m365copilot": "",
    },
    "azure_endpoint": "",
    "azure_deployment": "",
    "azure_api_version": "2024-08-01-preview",
    "m365_tenant_id": "",
    "m365_client_id": "",
}

# Per-provider environment-variable fallbacks for the API key.
ENV_KEYS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "google": "GOOGLE_API_KEY",
    "azure": "AZURE_OPENAI_API_KEY",
}

DEFAULT_SYSTEM_PROMPT = (
    "You are a senior security analyst. You will be given raw machine logs in "
    "which sensitive values have been redacted and replaced by bracketed "
    "placeholders such as [EMAIL_1], [IP_3], [USER_2], [APIKEY_1]. Treat each "
    "placeholder as a stable, opaque identifier: the same placeholder always "
    "refers to the same real value. Do NOT try to guess the real values. "
    "ALWAYS keep the placeholders verbatim in your answer (do not alter, split, "
    "translate, or reformat them) so they can be restored afterwards.\n\n"
    "Analyse the logs for security-relevant findings: signs of compromise, "
    "suspicious authentication, privilege escalation, data exfiltration, "
    "misconfigurations, anomalies, and indicators of attack. Be specific and "
    "reference the placeholder identifiers involved."
)

app = FastAPI(title="Log Masker")


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    logs: str
    categories: List[str] = ["identities", "network", "secrets"]
    custom_terms: List[str] = []
    instructions: Optional[str] = None   # extra guidance appended to the prompt


class PreviewRequest(BaseModel):
    logs: str
    categories: List[str] = ["identities", "network", "secrets"]
    custom_terms: List[str] = []


class ConfigRequest(BaseModel):
    provider: str
    make_default: bool = False        # set this provider as the default?
    provider_models: dict = {}        # per-provider default model overrides
    azure_endpoint: str = ""
    azure_deployment: str = ""
    azure_api_version: str = "2024-08-01-preview"
    m365_tenant_id: str = ""
    m365_client_id: str = ""


class KeyRequest(BaseModel):
    provider: str
    api_key: str


class ProviderRequest(BaseModel):
    provider: str


class TestRequest(BaseModel):
    provider: str
    model: str = ""
    azure_endpoint: str = ""
    azure_deployment: str = ""
    azure_api_version: str = "2024-08-01-preview"


# ---------------------------------------------------------------------------
# Config + key helpers
# ---------------------------------------------------------------------------
def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    cfg["provider_models"] = dict(DEFAULT_CONFIG["provider_models"])
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    # Merge the per-provider model map on top of defaults.
    pm = {**DEFAULT_CONFIG["provider_models"], **(data.get("provider_models") or {})}
    cfg.update({k: v for k, v in data.items() if k != "provider_models"})
    cfg["provider_models"] = pm
    # Migrate a legacy single "model" field into the per-provider map.
    if data.get("model") and not (data.get("provider_models") or {}).get(cfg["provider"]):
        cfg["provider_models"][cfg["provider"]] = data["model"]
    cfg.pop("model", None)
    return cfg


def save_config(cfg: dict) -> None:
    merged = dict(DEFAULT_CONFIG)
    merged.update(cfg)
    merged["provider_models"] = {**DEFAULT_CONFIG["provider_models"],
                                 **(cfg.get("provider_models") or {})}
    merged.pop("model", None)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2)


def resolve_model(cfg: dict, provider: str) -> str:
    """The default model for `provider`: the saved choice, else the registry
    default."""
    m = (cfg.get("provider_models") or {}).get(provider)
    return m or providers.PROVIDERS.get(provider, {}).get("default_model", "")


def public_config(cfg: dict) -> dict:
    """Config for the frontend, with a convenience `model` = the active
    (default-provider) model resolved."""
    out = dict(cfg)
    out["model"] = resolve_model(cfg, cfg.get("provider", ""))
    return out


def get_api_key(provider: str) -> Optional[str]:
    """Resolve a provider's key: keychain first, then env var."""
    try:
        k = keyring.get_password(KEYRING_SERVICE, f"{provider}_api_key")
        if k:
            return k.strip()
    except Exception:
        pass
    env = os.environ.get(ENV_KEYS.get(provider, ""), "")
    return env.strip() if env else None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/config")
def get_config():
    """Return current settings, the provider registry, and which providers
    have a key configured (booleans only -- never the keys themselves)."""
    cfg = load_config()
    configured = {}
    for pid in providers.PROVIDERS:
        if pid == "m365copilot":
            signed_in, _ = m365.status(cfg.get("m365_tenant_id", ""),
                                       cfg.get("m365_client_id", ""))
            configured[pid] = signed_in
        else:
            configured[pid] = bool(get_api_key(pid))
    return {
        "config": public_config(cfg),
        "providers": providers.public_registry(),
        "configured": configured,
    }


@app.post("/config")
def set_config(req: ConfigRequest):
    if req.provider not in providers.PROVIDERS:
        raise HTTPException(400, f"Unknown provider: {req.provider}")
    cfg = load_config()
    # Merge per-provider default-model choices.
    for pid, model in (req.provider_models or {}).items():
        if pid in providers.PROVIDERS:
            cfg["provider_models"][pid] = model
    # Global provider-specific fields.
    cfg["azure_endpoint"] = req.azure_endpoint
    cfg["azure_deployment"] = req.azure_deployment
    cfg["azure_api_version"] = req.azure_api_version
    cfg["m365_tenant_id"] = req.m365_tenant_id
    cfg["m365_client_id"] = req.m365_client_id
    # Optionally promote this provider to the default.
    if req.make_default:
        cfg["provider"] = req.provider
    save_config(cfg)
    return {"ok": True, "config": public_config(load_config())}


@app.get("/models")
def list_models(provider: str):
    """Live model list for a provider, fetched from its catalog API using the
    saved key. Empty list + a reason if unavailable; the UI falls back to the
    built-in list and always allows a custom model."""
    if provider not in providers.PROVIDERS:
        raise HTTPException(400, f"Unknown provider: {provider}")
    if provider in ("m365copilot", "azure"):
        return {"models": [], "error": "This provider has no listable catalog."}
    api_key = get_api_key(provider)
    if not api_key:
        return {"models": [], "error": "No API key saved for this provider."}
    try:
        models = providers.list_models(provider, api_key, load_config())
    except providers.ProviderError as e:
        return {"models": [], "error": str(e)}
    except Exception as e:
        return {"models": [], "error": str(e)[:300]}
    return {"models": models}


@app.post("/save-key")
def save_key(req: KeyRequest):
    if req.provider not in providers.PROVIDERS:
        raise HTTPException(400, f"Unknown provider: {req.provider}")
    try:
        keyring.set_password(KEYRING_SERVICE, f"{req.provider}_api_key",
                             req.api_key.strip())
    except Exception as e:
        raise HTTPException(500, f"Could not save key: {e}")
    return {"ok": True}


@app.post("/delete-key")
def delete_key(req: ProviderRequest):
    try:
        keyring.delete_password(KEYRING_SERVICE, f"{req.provider}_api_key")
    except Exception:
        pass
    return {"ok": True}


@app.post("/test")
def test_connection(req: TestRequest):
    """Send a tiny prompt to verify the provider actually works."""
    if req.provider == "m365copilot":
        cfg = load_config()
        try:
            reply = m365.chat(cfg.get("m365_tenant_id", ""),
                              cfg.get("m365_client_id", ""),
                              "Connection test.", "Reply with the word OK.")
        except m365.M365Error as e:
            raise HTTPException(502, str(e))
        return {"ok": True, "reply": reply[:200]}

    api_key = get_api_key(req.provider)
    if not api_key:
        raise HTTPException(400, "No API key configured for this provider.")
    cfg = req.dict()
    model = req.model or providers.PROVIDERS[req.provider]["default_model"]
    try:
        reply = providers.call(
            req.provider, api_key, model,
            "You are a connection test. Reply with the single word: OK.",
            "ping", cfg,
        )
    except providers.ProviderError as e:
        raise HTTPException(502, str(e))
    return {"ok": True, "reply": reply[:200]}


# --- Microsoft 365 Copilot OAuth (delegated) ----------------------------
def _redirect_uri(request: Request) -> str:
    # base_url ends with "/"; keep the scheme/host/port the browser actually used.
    return str(request.base_url) + "oauth/callback"


@app.get("/m365/redirect-uri")
def m365_redirect_uri(request: Request):
    """The exact redirect URI to register in the Entra app (Web platform)."""
    return {"redirect_uri": _redirect_uri(request)}


@app.get("/m365/login")
def m365_login(request: Request):
    cfg = load_config()
    try:
        url = m365.build_login_url(cfg.get("m365_tenant_id", ""),
                                   cfg.get("m365_client_id", ""),
                                   _redirect_uri(request))
    except m365.M365Error as e:
        raise HTTPException(400, str(e))
    return RedirectResponse(url)


@app.get("/oauth/callback", response_class=HTMLResponse)
def oauth_callback(request: Request):
    cfg = load_config()
    try:
        upn = m365.handle_callback(dict(request.query_params),
                                   cfg.get("m365_tenant_id", ""),
                                   cfg.get("m365_client_id", ""))
        msg = f"Signed in as {upn}. You can close this tab and return to Log Masker."
        ok = True
    except m365.M365Error as e:
        msg = f"Sign-in failed: {e}"
        ok = False
    color = "#3fb950" if ok else "#f85149"
    return (f"<html><body style='font-family:sans-serif;background:#0d1117;"
            f"color:#e6edf3;padding:40px'><h2 style='color:{color}'>"
            f"{'✓ Success' if ok else '✗ Error'}</h2><p>{msg}</p>"
            f"<script>setTimeout(()=>window.close(),2500);</script></body></html>")


@app.get("/m365/status")
def m365_status():
    cfg = load_config()
    signed_in, upn = m365.status(cfg.get("m365_tenant_id", ""),
                                 cfg.get("m365_client_id", ""))
    return {"signed_in": signed_in, "username": upn}


@app.post("/m365/logout")
def m365_logout():
    cfg = load_config()
    m365.logout(cfg.get("m365_tenant_id", ""), cfg.get("m365_client_id", ""))
    return {"ok": True}


@app.post("/preview")
def preview(req: PreviewRequest):
    """Mask locally and return the masked text + mapping, without any API call.
    Lets you see exactly what would be sent before sending it."""
    masked, mapping = masker.mask(req.logs, req.categories, req.custom_terms)
    return {"masked": masked, "mapping": mapping, "count": len(mapping)}


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    cfg = load_config()
    provider = cfg["provider"]

    # 1. Mask locally.
    masked, mapping = masker.mask(req.logs, req.categories, req.custom_terms)

    # 2. Build the prompt and call the provider with ONLY the masked text.
    system = DEFAULT_SYSTEM_PROMPT
    if req.instructions:
        system += "\n\nAdditional user instructions:\n" + req.instructions.strip()

    if provider == "m365copilot":
        model = "microsoft-365-copilot"
        try:
            raw_response = m365.chat(cfg.get("m365_tenant_id", ""),
                                     cfg.get("m365_client_id", ""),
                                     system, masked)
        except m365.M365Error as e:
            raise HTTPException(502, str(e))
    else:
        api_key = get_api_key(provider)
        if not api_key:
            label = providers.PROVIDERS.get(provider, {}).get("label", provider)
            raise HTTPException(
                400, f"No API key configured for {label}. Open Setup to add one.")
        model = resolve_model(cfg, provider)
        try:
            raw_response = providers.call(provider, api_key, model, system, masked, cfg)
        except providers.ProviderError as e:
            raise HTTPException(502, str(e))

    # 3. Restore real values locally.
    restored = masker.unmask(raw_response, mapping)

    return {
        "provider": provider,
        "model": model,
        "masked_sent": masked,                # what actually left the machine
        "mapping": mapping,                   # placeholder -> real (local only)
        "masked_count": len(mapping),
        "ai_response_masked": raw_response,   # response as returned
        "ai_response_restored": restored,     # final, un-masked result
    }


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
