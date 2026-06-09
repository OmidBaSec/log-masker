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

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import masker
import providers

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
DEFAULT_CONFIG = {
    "provider": "anthropic",
    "model": "claude-opus-4-8",
    "azure_endpoint": "",
    "azure_deployment": "",
    "azure_api_version": "2024-08-01-preview",
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
    model: str = ""
    azure_endpoint: str = ""
    azure_deployment: str = ""
    azure_api_version: str = "2024-08-01-preview"


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
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return cfg


def save_config(cfg: dict) -> None:
    merged = dict(DEFAULT_CONFIG)
    merged.update(cfg)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2)


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
    configured = {pid: bool(get_api_key(pid)) for pid in providers.PROVIDERS}
    return {
        "config": cfg,
        "providers": providers.public_registry(),
        "configured": configured,
    }


@app.post("/config")
def set_config(req: ConfigRequest):
    if req.provider not in providers.PROVIDERS:
        raise HTTPException(400, f"Unknown provider: {req.provider}")
    save_config(req.dict())
    return {"ok": True, "config": load_config()}


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
    """Send a tiny prompt to verify the provider/key/model actually work."""
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
    api_key = get_api_key(provider)
    if not api_key:
        label = providers.PROVIDERS.get(provider, {}).get("label", provider)
        raise HTTPException(
            400, f"No API key configured for {label}. Open Setup to add one.")

    model = cfg.get("model") or providers.PROVIDERS[provider]["default_model"]

    # 1. Mask locally.
    masked, mapping = masker.mask(req.logs, req.categories, req.custom_terms)

    # 2. Build the prompt and call the provider with ONLY the masked text.
    system = DEFAULT_SYSTEM_PROMPT
    if req.instructions:
        system += "\n\nAdditional user instructions:\n" + req.instructions.strip()

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
