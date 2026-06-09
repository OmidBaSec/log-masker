"""
Log Masker -- a local web app that scrubs sensitive data from raw logs before
sending them to the Claude API for security analysis, then restores the real
values in the response.

Flow:
  1. You paste raw logs in the browser and pick which data types to mask.
  2. The server masks them LOCALLY (see masker.py) -- only placeholders leave
     this machine.
  3. The masked text is sent to the Claude API for analysis.
  4. The masked placeholders in Claude's response are replaced back with the
     real values, locally, and shown to you.

The mask -> real mapping never leaves the server process.
"""

import os
import sys
import json
import keyring
import requests
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import masker

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
KEYRING_SERVICE = "log_masker"
KEYRING_USER = "anthropic_api_key"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

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
# Models
# ---------------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    logs: str
    categories: List[str] = ["identities", "network", "secrets"]
    custom_terms: List[str] = []        # exact strings to always mask
    model: str = "claude-opus-4-8"
    instructions: Optional[str] = None  # extra user guidance appended to prompt
    api_key: Optional[str] = None       # optional one-off key (not stored)


class PreviewRequest(BaseModel):
    logs: str
    categories: List[str] = ["identities", "network", "secrets"]
    custom_terms: List[str] = []


class KeyRequest(BaseModel):
    api_key: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _resolve_api_key(inline: Optional[str]) -> Optional[str]:
    if inline:
        return inline.strip()
    env = os.environ.get("ANTHROPIC_API_KEY")
    if env:
        return env.strip()
    try:
        return keyring.get_password(KEYRING_SERVICE, KEYRING_USER)
    except Exception:
        return None


def _call_claude(api_key: str, model: str, system: str, user_text: str) -> str:
    headers = {
        "x-api-key": api_key,
        "anthropic-version": ANTHROPIC_VERSION,
        "content-type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": 4096,
        "system": system,
        "messages": [{"role": "user", "content": user_text}],
    }
    resp = requests.post(ANTHROPIC_URL, headers=headers,
                         data=json.dumps(payload), timeout=120)
    if resp.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"Claude API error {resp.status_code}: {resp.text[:500]}",
        )
    data = resp.json()
    parts = [b.get("text", "") for b in data.get("content", [])
             if b.get("type") == "text"]
    return "".join(parts).strip()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.post("/preview")
def preview(req: PreviewRequest):
    """Mask locally and return the masked text + mapping, without any API call.

    Lets you see exactly what would be sent before sending it."""
    masked, mapping = masker.mask(req.logs, req.categories, req.custom_terms)
    return {
        "masked": masked,
        "mapping": mapping,
        "count": len(mapping),
    }


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    api_key = _resolve_api_key(req.api_key)
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="No Anthropic API key. Save one in Settings, set "
                   "ANTHROPIC_API_KEY, or paste a one-off key.",
        )

    # 1. Mask locally.
    masked, mapping = masker.mask(req.logs, req.categories, req.custom_terms)

    # 2. Build the prompt and call Claude with ONLY the masked text.
    system = DEFAULT_SYSTEM_PROMPT
    if req.instructions:
        system += "\n\nAdditional user instructions:\n" + req.instructions.strip()

    raw_response = _call_claude(api_key, req.model, system, masked)

    # 3. Restore real values locally.
    restored = masker.unmask(raw_response, mapping)

    return {
        "masked_sent": masked,        # what actually left the machine
        "mapping": mapping,           # placeholder -> real (local only)
        "masked_count": len(mapping),
        "ai_response_masked": raw_response,   # response as Claude returned it
        "ai_response_restored": restored,     # final, un-masked result
    }


@app.get("/key-status")
def key_status():
    return {"has_key": bool(_resolve_api_key(None))}


@app.post("/save-key")
def save_key(req: KeyRequest):
    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_USER, req.api_key.strip())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not save key: {e}")
    return {"ok": True}


@app.post("/delete-key")
def delete_key():
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_USER)
    except Exception:
        pass
    return {"ok": True}


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
