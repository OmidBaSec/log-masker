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
import re
import sys
import json
import time
import uuid
import keyring
from collections import deque
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import masker
import providers
import m365
import templates
import verdict as verdict_mod
import leakguard
import store

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
    structured: bool = True              # ask the model for a verdict schema
    acknowledge_leaks: bool = False      # analyst confirmed leak-guard findings
    use_system: bool = True              # send the saved system prompt?


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


class PatternRequest(BaseModel):
    label: str
    regex: str


class PatternDeleteRequest(BaseModel):
    index: int


class BuiltinPatternRequest(BaseModel):
    id: str
    regex: str


class BuiltinPatternResetRequest(BaseModel):
    id: str


class FollowUpRequest(BaseModel):
    conversation_id: str
    question: str
    acknowledge_leaks: bool = False


class EndConversationRequest(BaseModel):
    conversation_id: str


class SuggestRequest(BaseModel):
    logs: str
    limit: int = 3


class CustomTermsRequest(BaseModel):
    terms: List[str] = []


class SystemPromptRequest(BaseModel):
    prompt: str


class TemplateSaveRequest(BaseModel):
    id: str
    name: Optional[str] = None
    category: Optional[str] = None
    tactic: Optional[str] = None
    tactic_id: Optional[str] = None
    technique: Optional[str] = None
    technique_id: Optional[str] = None
    prompt: Optional[str] = None
    keywords: Optional[List[str]] = None


class TemplateCreateRequest(BaseModel):
    name: str
    prompt: str
    category: str = "Custom"
    tactic: str = "Custom"
    tactic_id: str = ""
    technique: str = ""
    technique_id: str = ""
    keywords: List[str] = []


class TemplateIdRequest(BaseModel):
    id: str


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


def get_system_prompt(cfg: dict) -> str:
    """The effective system prompt: the user's saved override if present,
    otherwise the built-in default."""
    saved = (cfg.get("system_prompt") or "").strip()
    return saved or DEFAULT_SYSTEM_PROMPT


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
    """Send a tiny prompt to verify the provider actually works. Goes through
    the same logged path as real analyses, so it shows up under Requests."""
    if req.provider not in providers.PROVIDERS:
        raise HTTPException(400, f"Unknown provider: {req.provider}")
    if req.provider == "m365copilot":
        cfg = load_config()
        model = "microsoft-365-copilot"
    else:
        cfg = req.dict()
        model = req.model or providers.PROVIDERS[req.provider]["default_model"]
    reply = _call_provider_chat(
        cfg, req.provider, model,
        "You are a connection test. Reply with the single word: OK.",
        [{"role": "user", "content": "ping"}], kind="test")
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


# --- System prompt (editable, persisted in config) ------------------------
@app.get("/system_prompt")
def get_system_prompt_route():
    cfg = load_config()
    return {
        "prompt": get_system_prompt(cfg),
        "default": DEFAULT_SYSTEM_PROMPT,
        "is_custom": bool((cfg.get("system_prompt") or "").strip()),
    }


@app.post("/system_prompt")
def save_system_prompt(req: SystemPromptRequest):
    prompt = req.prompt.strip()
    if not prompt:
        raise HTTPException(400, "The system prompt must not be empty.")
    cfg = load_config()
    cfg["system_prompt"] = prompt
    save_config(cfg)
    return {"ok": True, "prompt": prompt, "is_custom": True}


@app.post("/system_prompt/reset")
def reset_system_prompt():
    cfg = load_config()
    cfg.pop("system_prompt", None)
    save_config(cfg)
    return {"ok": True, "prompt": DEFAULT_SYSTEM_PROMPT, "is_custom": False}


# --- Custom always-mask terms (persisted locally) -------------------------
@app.get("/custom_terms")
def get_custom_terms():
    return {"terms": store.get_terms()}


@app.post("/custom_terms")
def save_custom_terms(req: CustomTermsRequest):
    """Persist the custom always-mask terms."""
    store.set_terms(req.terms)
    return {"ok": True, "terms": store.get_terms()}


def _merged_terms(request_terms: List[str]) -> List[str]:
    """Terms from the request plus the saved terms — the saved dictionary
    always applies, even if the UI is stale."""
    return list(dict.fromkeys([t.strip() for t in (request_terms or [])
                               if t.strip()] + store.get_terms()))


# --- Saved regex patterns (applied to every mask run) ---------------------
@app.get("/patterns")
def list_patterns():
    return {"patterns": store.get_patterns()}


@app.post("/patterns")
def add_pattern(req: PatternRequest):
    label = req.label.strip()
    regex = req.regex.strip()
    if not label or not regex:
        raise HTTPException(400, "Both label and regex are required.")
    try:
        re.compile(regex)
    except re.error as e:
        raise HTTPException(400, f"Invalid regex: {e}")
    try:
        store.add_pattern(label, regex)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "patterns": store.get_patterns()}


@app.post("/patterns/delete")
def delete_pattern(req: PatternDeleteRequest):
    try:
        store.delete_pattern(req.index)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "patterns": store.get_patterns()}


# --- Built-in masking patterns (per log source, editable) ----------------
@app.get("/builtin_patterns")
def list_builtin_patterns():
    """Every built-in pattern with its log source, field label, effective
    regex, default regex, and whether it has been customised."""
    return {"patterns": masker.get_builtin_patterns()}


@app.post("/builtin_patterns")
def update_builtin_pattern(req: BuiltinPatternRequest):
    regex = req.regex.strip()
    if not regex:
        raise HTTPException(400, "Regex must not be empty — use Reset to "
                                 "restore the default.")
    try:
        masker.set_builtin_pattern(req.id, regex)
    except re.error as e:
        raise HTTPException(400, f"Invalid regex: {e}")
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@app.post("/builtin_patterns/reset")
def reset_builtin_pattern(req: BuiltinPatternResetRequest):
    masker.reset_builtin_pattern(req.id)
    return {"ok": True}


# --- SOC analyst prompt-template library ---------------------------------
@app.get("/templates")
def get_templates():
    """The full prompt-template library (with MITRE ATT&CK mappings)."""
    return {"templates": templates.list_templates()}


@app.post("/templates/suggest")
def suggest_templates(req: SuggestRequest):
    """Suggest the most relevant templates for a raw log. Runs locally on the
    raw text; only template ids + scores are returned, never log content."""
    return {"suggestions": templates.suggest(req.logs, limit=req.limit)}


@app.post("/templates/save")
def save_template(req: TemplateSaveRequest):
    """Edit an existing template (built-in override or custom in place)."""
    fields = {k: v for k, v in req.dict().items()
              if k != "id" and v is not None}
    try:
        tpl = templates.save_template(req.id, fields)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "template": tpl}


@app.post("/templates/create")
def create_template(req: TemplateCreateRequest):
    """Create a new custom template (optionally with suggestion keywords)."""
    try:
        tpl = templates.create_template(req.dict())
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "template": tpl}


@app.post("/templates/delete")
def delete_template(req: TemplateIdRequest):
    try:
        templates.delete_template(req.id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@app.post("/templates/reset")
def reset_template(req: TemplateIdRequest):
    try:
        tpl = templates.reset_template(req.id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "template": tpl}


@app.post("/preview")
def preview(req: PreviewRequest):
    """Mask locally and return the masked text + mapping, without any API call.
    Lets you see exactly what would be sent before sending it."""
    terms = _merged_terms(req.custom_terms)
    masked, mapping = masker.mask(req.logs, req.categories, terms,
                                  store.get_patterns())
    warnings = leakguard.scan(masked, mapping, terms, req.categories)
    return {"masked": masked, "mapping": mapping, "count": len(mapping),
            "warnings": warnings}


# ---------------------------------------------------------------------------
# Conversations. Each "Mask & Analyse" starts one; follow-up questions are sent
# with the full (masked) history so the AI keeps context. State lives only in
# this process's memory — ending the conversation (or restarting the server)
# forgets it. The cumulative mapping keeps placeholders consistent across turns.
# ---------------------------------------------------------------------------
CONVERSATIONS: dict = {}

# Audit log of every outbound AI request (masked content only — that is the
# whole point). Each entry is appended to AI_REQUESTS_FILE as one JSON line,
# so there is a permanent on-disk audit trail to verify that no customer data
# ever left the machine. The in-memory deque feeds the Requests tab.
AI_REQUESTS_FILE = os.path.join(APP_DIR, "ai_requests.jsonl")
REQUEST_LOG: deque = deque(maxlen=200)
_REQUEST_SEQ = {"n": 0}


def _log_request(kind: str, provider: str, model: str, system: str,
                 messages: list, response: str, error: str,
                 duration_ms: int, conversation_id: Optional[str],
                 leak_info: Optional[dict] = None) -> None:
    _REQUEST_SEQ["n"] += 1
    entry = {
        "seq": _REQUEST_SEQ["n"],
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "kind": kind,                       # analyze | follow-up | test
        "provider": provider,
        "model": model,
        "conversation_id": conversation_id,
        "system": system,
        "messages": [dict(m) for m in messages],   # masked, as sent
        "response": response,                      # masked, as received
        "error": error,
        "ok": not error,
        "duration_ms": duration_ms,
    }
    if leak_info:
        # Leak-guard findings the analyst acknowledged before this was sent —
        # part of the audit trail by design.
        entry["leakguard"] = leak_info
    REQUEST_LOG.append(entry)
    # Append-only audit file. Never let audit I/O break the request itself.
    try:
        with open(AI_REQUESTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _load_request_log() -> None:
    """Reload the most recent audit entries on startup, so the Requests tab
    (and the seq numbering) survives server restarts."""
    try:
        with open(AI_REQUESTS_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return
    for line in lines[-(REQUEST_LOG.maxlen or 200):]:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict) and entry.get("time"):
            REQUEST_LOG.append(entry)
            try:
                _REQUEST_SEQ["n"] = max(_REQUEST_SEQ["n"],
                                        int(entry.get("seq", 0)))
            except (TypeError, ValueError):
                pass


_load_request_log()


def _call_provider_chat(cfg: dict, provider: str, model: str,
                        system: str, messages: list,
                        kind: str = "analyze",
                        conversation_id: Optional[str] = None,
                        leak_info: Optional[dict] = None) -> str:
    """Send a masked conversation to the provider; returns the response text.
    Every attempt — success or failure — is recorded in REQUEST_LOG."""
    start = time.time()
    response, error = "", ""
    try:
        if provider == "m365copilot":
            # The Copilot Chat API takes a single prompt; flatten the history.
            parts = []
            for m in messages:
                who = "ANALYST" if m["role"] == "user" else "YOUR PREVIOUS ANSWER"
                parts.append(f"{who}:\n{m['content']}")
            try:
                response = m365.chat(cfg.get("m365_tenant_id", ""),
                                     cfg.get("m365_client_id", ""),
                                     system, "\n\n".join(parts))
            except m365.M365Error as e:
                raise HTTPException(502, str(e))
            return response
        api_key = get_api_key(provider)
        if not api_key:
            label = providers.PROVIDERS.get(provider, {}).get("label", provider)
            raise HTTPException(
                400, f"No API key configured for {label}. Open Setup to add one.")
        try:
            response = providers.call(provider, api_key, model, system,
                                      messages, cfg)
        except providers.ProviderError as e:
            raise HTTPException(502, str(e))
        return response
    except HTTPException as e:
        error = str(e.detail)
        raise
    finally:
        _log_request(kind, provider, model, system, messages, response, error,
                     int((time.time() - start) * 1000), conversation_id,
                     leak_info)


def _shape_response(masked_response: str, mapping: dict, structured: bool) -> dict:
    """Split a masked AI response into restored prose + a restored verdict
    object (when structured). The verdict is parsed on the masked text, then
    its placeholders are restored — never the reverse."""
    if structured:
        prose_masked, v = verdict_mod.split_response(masked_response)
    else:
        prose_masked, v = masked_response, None
    return {
        "ai_response_masked": masked_response,
        "ai_response_restored": masker.unmask(prose_masked, mapping),
        "verdict": (verdict_mod.restore(v, masker.unmask, mapping) if v else None),
    }


@app.get("/requests")
def list_requests():
    """The outbound AI requests, newest first (masked content only)."""
    return {"requests": list(REQUEST_LOG)[::-1], "file": AI_REQUESTS_FILE}


@app.post("/requests/clear")
def clear_requests():
    """Clears the in-memory view only. The on-disk audit file is append-only
    and is deliberately never deleted by the app."""
    REQUEST_LOG.clear()
    return {"ok": True, "file": AI_REQUESTS_FILE}


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    """Mask the logs, send them to the AI, and start a conversation that
    follow-up questions (/chat) can continue."""
    cfg = load_config()
    provider = cfg["provider"]
    model = ("microsoft-365-copilot" if provider == "m365copilot"
             else resolve_model(cfg, provider))

    # 1. Mask locally with the saved dictionary.
    terms = _merged_terms(req.custom_terms)
    masked, mapping = masker.mask(req.logs, req.categories, terms,
                                  store.get_patterns())

    # 2. Pre-send leak guard: independent second pass over the MASKED text.
    #    Blocking findings stop everything here — nothing has left the machine
    #    and no conversation exists — until the analyst acknowledges.
    warnings = leakguard.scan(masked, mapping, terms, req.categories)
    if leakguard.has_blocking(warnings) and not req.acknowledge_leaks:
        return {"blocked": True, "warnings": warnings,
                "masked_count": len(mapping)}
    leak_info = ({"warnings": warnings, "acknowledged": req.acknowledge_leaks}
                 if warnings else None)

    # 3. Build the prompt and call the provider with ONLY the masked text.
    #    The system prompt is optional — the analyst can turn it off per run.
    system = get_system_prompt(cfg) if req.use_system else ""
    if req.instructions:
        sep = "\n\nAdditional user instructions:\n" if system else ""
        system += sep + req.instructions.strip()
    if req.structured:
        system += verdict_mod.SCHEMA_PROMPT

    conv_id = uuid.uuid4().hex[:12]
    messages = [{"role": "user", "content": masked}]
    raw_response = _call_provider_chat(cfg, provider, model, system, messages,
                                       kind="analyze", conversation_id=conv_id,
                                       leak_info=leak_info)
    messages.append({"role": "assistant", "content": raw_response})

    # 4. Remember the conversation so follow-ups keep the AI's context.
    CONVERSATIONS[conv_id] = {
        "provider": provider, "model": model, "system": system,
        "messages": messages, "mapping": mapping,
        "categories": req.categories, "custom_terms": terms,
        "structured": req.structured,
    }

    # 5. Restore real values locally (prose + structured verdict).
    shaped = _shape_response(raw_response, mapping, req.structured)

    return {
        "provider": provider,
        "model": model,
        "conversation_id": conv_id,
        "transcript": messages,               # masked history (what left/leaves)
        "masked_sent": masked,                # what actually left the machine
        "mapping": mapping,                   # placeholder -> real (local only)
        "masked_count": len(mapping),
        "warnings": warnings,                 # leak-guard findings (if any)
        **shaped,                             # restored prose + verdict
    }


@app.post("/chat")
def chat_followup(req: FollowUpRequest):
    """Ask a follow-up question in an existing conversation. The question is
    masked with the conversation's cumulative mapping (a value masked earlier
    is re-masked with the same placeholder even if typed verbatim), and the
    full masked history is sent so the AI remembers previous turns."""
    conv = CONVERSATIONS.get(req.conversation_id)
    if not conv:
        raise HTTPException(404, "This conversation has ended (or the server "
                                 "restarted). Analyse a log to start a new one.")
    question = req.question.strip()
    if not question:
        raise HTTPException(400, "The question is empty.")

    masked_q, mapping = masker.mask(question, conv["categories"],
                                    conv["custom_terms"],
                                    store.get_patterns(),
                                    conv["mapping"])
    # Pre-send leak guard on the masked question (an analyst can paste raw
    # log content into a follow-up too). Nothing is appended or sent while
    # blocked.
    warnings = leakguard.scan(masked_q, mapping, conv["custom_terms"],
                              conv["categories"])
    if leakguard.has_blocking(warnings) and not req.acknowledge_leaks:
        return {"blocked": True, "warnings": warnings,
                "conversation_id": req.conversation_id}
    leak_info = ({"warnings": warnings, "acknowledged": req.acknowledge_leaks}
                 if warnings else None)

    conv["messages"].append({"role": "user", "content": masked_q})
    try:
        raw_response = _call_provider_chat(load_config(), conv["provider"],
                                           conv["model"], conv["system"],
                                           conv["messages"], kind="follow-up",
                                           conversation_id=req.conversation_id,
                                           leak_info=leak_info)
    except HTTPException:
        conv["messages"].pop()    # don't poison the history with a failed turn
        raise
    conv["messages"].append({"role": "assistant", "content": raw_response})
    conv["mapping"] = mapping

    shaped = _shape_response(raw_response, mapping, conv.get("structured", False))
    return {
        "provider": conv["provider"],
        "model": conv["model"],
        "conversation_id": req.conversation_id,
        "transcript": conv["messages"],
        "masked_question": masked_q,
        "mapping": mapping,
        "masked_count": len(mapping),
        **shaped,                             # restored prose + (updated) verdict
    }


@app.post("/chat/end")
def chat_end(req: EndConversationRequest):
    """Forget a conversation (history + mapping), freeing the UI for a new log."""
    CONVERSATIONS.pop(req.conversation_id, None)
    return {"ok": True}


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
