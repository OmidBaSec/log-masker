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
OS keychain where the platform has one and in an encrypted file where it does
not (see keystore.py); non-secret settings live in app_config.json, inside the
per-OS data directory resolved by paths.py.
"""

import os
import re
import sys
import html
import json
import time
import uuid
from collections import deque
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.responses import (HTMLResponse, FileResponse,
                               JSONResponse, RedirectResponse)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from log_masker import guard
from log_masker import keystore
from log_masker import masker
from log_masker import paths
from log_masker import providers
from log_masker import regexlab
from log_masker import m365
from log_masker import templates
from log_masker import verdict as verdict_mod
from log_masker import leakguard
from log_masker import store
from log_masker import vault
from log_masker import pricing
from log_masker import usage

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
# The code lives wherever it was installed; data lives wherever paths.py says
# (see it for the per-OS rules). Only STATIC_DIR is tied to the code.
VERSION = "0.9.0"

# Spreadsheet import limits. openpyxl on an untrusted archive is the one place
# this app does heavy parsing of a file it did not create.
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_EXPANDED_BYTES = 200 * 1024 * 1024
MAX_EXPANSION_RATIO = 200
MAX_CELLS = 2_000_000
MAX_PARSE_SECONDS = 60

APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(APP_DIR, "static")
CONFIG_FILE = paths.data_file("app_config.json")

# Non-secret settings persisted to CONFIG_FILE.
#   provider         -> the DEFAULT provider used for analysis
#   provider_models  -> the DEFAULT model chosen for EACH provider
DEFAULT_CONFIG = {
    "provider": "anthropic",
    "provider_models": {
        "anthropic": "claude-opus-5",
        "openai": "gpt-6-astra",
        "google": "gemini-3.8-flash",
        "azure": "",
        "m365copilot": "",
        "ollama": "",
    },
    "ollama_endpoint": "",
    "azure_endpoint": "",
    "azure_deployment": "",
    "azure_api_version": "2024-08-01-preview",
    "m365_tenant_id": "",
    "m365_client_id": "",
    "vault_enabled": True,
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
    "Analyze the logs for security-relevant findings: signs of compromise, "
    "suspicious authentication, privilege escalation, data exfiltration, "
    "misconfigurations, anomalies, and indicators of attack. Be specific and "
    "reference the placeholder identifiers involved."
)

app = FastAPI(title="Log Masker", version=VERSION)


# A local server with no login is only as safe as its provenance checks; see
# guard.py for what each one stops. Startup is refused outright when the app is
# being bound somewhere the whole network can reach.
_BIND_PROBLEM = guard.startup_check()
if _BIND_PROBLEM:
    raise RuntimeError(_BIND_PROBLEM)


@app.middleware("http")
async def request_guard(request: Request, call_next):
    problem = guard.check(request.method, request.headers)
    if problem:
        response = JSONResponse({"detail": problem}, status_code=403)
    else:
        response = await call_next(request)
    # On every response, including the 403 above and the files served by the
    # static mount. A header that covers only some routes is one route away
    # from being no protection at all -- and the route an attacker frames is
    # "/", which is a FileResponse, not a JSON endpoint.
    guard.apply_security_headers(response.headers)
    return response


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
    vault_context: bool = True           # attach cross-incident entity history
                                         # (placeholder stats only) to the prompt


class PreviewRequest(BaseModel):
    logs: str
    categories: List[str] = ["identities", "network", "secrets"]
    custom_terms: List[str] = []


class PromptPreviewRequest(BaseModel):
    logs: str
    categories: List[str] = ["identities", "network", "secrets"]
    custom_terms: List[str] = []
    instructions: Optional[str] = None
    structured: bool = True
    use_system: bool = True
    vault_context: bool = True


class ConfigRequest(BaseModel):
    provider: str
    make_default: bool = False        # set this provider as the default?
    provider_models: dict = {}        # per-provider default model overrides
    ollama_endpoint: str = ""
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


class KeepTermRequest(BaseModel):
    term: str
    forget_from_vault: bool = True


class RegexLabRequest(BaseModel):
    sample: str
    value: str
    label: Optional[str] = None
    categories: Optional[List[str]] = None


class RegexTryRequest(BaseModel):
    sample: str
    regex: str
    label: str = "CUSTOM"
    categories: Optional[List[str]] = None


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


class VaultEnabledRequest(BaseModel):
    enabled: bool


class VaultForgetRequest(BaseModel):
    placeholder: str


class RateRequest(BaseModel):
    model: str
    input_per_m: float
    output_per_m: float


class TestRequest(BaseModel):
    provider: str
    model: str = ""
    ollama_endpoint: str = ""
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


def build_system(cfg: dict, use_system: bool, instructions: Optional[str],
                 structured: bool) -> str:
    """Assemble the exact system prompt sent to the provider: the saved system
    prompt (optional), any extra instructions, and the structured-verdict
    schema (optional). Shared by /analyze and /preview_prompt so the preview
    matches what is actually sent."""
    system = get_system_prompt(cfg) if use_system else ""
    if instructions and instructions.strip():
        sep = "\n\nAdditional user instructions:\n" if system else ""
        system += sep + instructions.strip()
    if structured:
        system += verdict_mod.SCHEMA_PROMPT
    return system


def get_api_key(provider: str) -> Optional[str]:
    """Resolve a provider's key: the OS keychain or its encrypted-file stand-in,
    then the provider's environment variable. See keystore.py."""
    return keystore.get_secret(f"{provider}_api_key",
                               ENV_KEYS.get(provider, ""))


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
        elif not providers.needs_key(pid):
            # Keyless local provider: "configured" means the endpoint answers.
            configured[pid] = providers.reachable(pid, cfg)
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
    cfg["ollama_endpoint"] = req.ollama_endpoint
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
    if not api_key and providers.needs_key(provider):
        return {"models": [], "error": "No API key saved for this provider."}
    try:
        models = providers.list_models(provider, api_key or "", load_config())
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
        where = keystore.set_secret(f"{req.provider}_api_key",
                                    req.api_key.strip())
    except Exception as e:
        raise HTTPException(500, f"Could not save key: {e}")
    return {"ok": True, "stored_in": where}


@app.post("/delete-key")
def delete_key(req: ProviderRequest):
    keystore.delete_secret(f"{req.provider}_api_key")
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
    # `msg` carries text from the identity provider (an error_description, or
    # the UPN from the token claims). This page is served from the app's own
    # origin, so markup smuggled through it would run as same-origin script —
    # with the request guard treating it as us. Escape it.
    color = "#3fb950" if ok else "#f85149"
    return (f"<html><body style='font-family:sans-serif;background:#0d1117;"
            f"color:#e6edf3;padding:40px'><h2 style='color:{color}'>"
            f"{'✓ Success' if ok else '✗ Error'}</h2><p>{html.escape(msg)}</p>"
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


# --- Persistent entity vault (cross-incident placeholder memory) ----------
def _vault_on(cfg: dict) -> bool:
    return bool(cfg.get("vault_enabled", True)) and vault.available()[0]


def _vault_seed(cfg: dict):
    """(base_mapping, base_counters) for masker.mask(): the vault's
    placeholder->real mapping keeps placeholders stable across incidents (not
    just across turns), and the counter floors keep a forgotten entity's
    number retired."""
    if _vault_on(cfg):
        return vault.mapping(), vault.counters()
    return None, None


def _used_mapping(mapping: dict, *texts: str) -> dict:
    """Trim a cumulative mapping to the placeholders that actually occur in
    `texts`. With the vault seeding every mask run, the cumulative mapping
    contains the WHOLE vault — the UI and the response should only show the
    entities of this log/conversation. (Substring test is safe: the closing
    bracket means "[USER_1]" can never match inside "[USER_10]".)"""
    return {ph: real for ph, real in mapping.items()
            if any(ph in t for t in texts)}


def _vault_context_block(lines: List[str]) -> str:
    """A prompt block with the vault's history for recurring entities.
    Placeholder ids, dates, counts, and verdict labels only — the block is
    part of the masked payload and must stay as anonymous as the log."""
    if not lines:
        return ""
    return (
        "\n\nCross-incident context from the analyst's local entity vault. "
        "Placeholders are stable across ALL past analyses on this system, so "
        "the same placeholder in the history below refers to the same real "
        "entity as in the log. Use this to judge whether an entity is a "
        "repeat offender, a known-benign regular, or newly seen:\n- "
        + "\n- ".join(lines))


@app.get("/vault")
def vault_overview():
    """Vault status + every entity with its incident history. Real values are
    included — this endpoint is local-only, like the mapping in /preview."""
    cfg = load_config()
    avail, reason = vault.available()
    out = {"enabled": bool(cfg.get("vault_enabled", True)),
           "available": avail, "reason": reason,
           "warning": vault.status_warning() if avail else "",
           "file": vault.VAULT_FILE,
           # Where the key actually lives on THIS machine. The UI used to say
           # "your OS keychain", which is wrong on a headless Linux box or in
           # a container -- exactly where a shared deployment runs.
           "key_backend": keystore.backend()}
    if avail:
        out["stats"] = vault.stats()
        out["entities"] = vault.entities()
    else:
        out["stats"] = {"entities": 0, "incidents": 0, "labels": {}}
        out["entities"] = []
    return out


@app.post("/vault/enabled")
def vault_set_enabled(req: VaultEnabledRequest):
    cfg = load_config()
    cfg["vault_enabled"] = req.enabled
    save_config(cfg)
    return {"ok": True, "enabled": req.enabled}


@app.post("/vault/forget")
def vault_forget(req: VaultForgetRequest):
    """Remove one entity. Its number is retired — never reused for a new
    value — so old analyses can't silently point at a different entity."""
    if not vault.forget(req.placeholder.strip()):
        raise HTTPException(404, "No such entity in the vault.")
    return {"ok": True}


@app.post("/vault/clear")
def vault_clear():
    vault.clear()
    return {"ok": True}


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


# --- Never-mask list ------------------------------------------------------
# The mirror of custom terms, for the other half of the problem: masking fired
# on something that identifies nobody. Editing a regex is the right answer
# when a whole *class* of value is wrong; when one particular value is wrong,
# this is.
@app.get("/keep_terms")
def list_keep_terms():
    return {"terms": store.get_keep_terms()}


@app.post("/keep_terms")
def add_keep_term(req: KeepTermRequest):
    """Rule one value non-sensitive, and stop the vault re-masking it.

    Forgetting the vault entry matters as much as the rule itself: the vault
    re-masks every value it has ever seen, so a value learned before the
    ruling would keep coming back masked and the rule would look broken."""
    term = (req.term or "").strip()
    try:
        store.add_keep_term(term)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    forgotten = []
    if req.forget_from_vault:
        for entity in vault.entities():
            if (entity.get("value") or "").strip().lower() == term.lower():
                if vault.forget(entity["placeholder"]):
                    forgotten.append(entity["placeholder"])
    return {"ok": True, "terms": store.get_keep_terms(),
            "forgotten": forgotten}


@app.post("/keep_terms/delete")
def delete_keep_term(req: KeepTermRequest):
    store.delete_keep_term(req.term)
    return {"ok": True, "terms": store.get_keep_terms()}


# --- Regex workbench ------------------------------------------------------
# Everything here runs on this machine. The whole reason it exists is that a
# log too sensitive to send to a provider is also too sensitive to paste into
# an online regex tester, so the tool that fixes the masking has to live
# behind the same wall as the data.
@app.post("/regexlab/suggest")
def regexlab_suggest(req: RegexLabRequest):
    """Why did this value survive masking, and what regex change fixes it?"""
    return regexlab.suggest(req.sample, req.value, req.label, req.categories)


@app.post("/regexlab/try")
def regexlab_try(req: RegexTryRequest):
    """Run one candidate against the sample without saving anything."""
    return regexlab.try_regex(req.sample, req.regex, req.label, req.categories)


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
    cfg = load_config()
    terms = _merged_terms(req.custom_terms)
    base, floors = _vault_seed(cfg)
    masked, mapping = masker.mask(req.logs, req.categories, terms,
                                  store.get_patterns(), base, floors, keep_terms=store.get_keep_terms())
    warnings = leakguard.scan(masked, mapping, terms, req.categories,
                             keep_terms=store.get_keep_terms())
    used = _used_mapping(mapping, masked)
    return {"masked": masked, "mapping": used, "count": len(used),
            "warnings": warnings}


@app.post("/preview_prompt")
def preview_prompt(req: PromptPreviewRequest):
    """Assemble the EXACT prompt that would be sent: the system prompt (with any
    instructions/schema) plus the masked log as the user message. No API call —
    lets the analyst review the full prompt before sending."""
    cfg = load_config()
    terms = _merged_terms(req.custom_terms)
    base, floors = _vault_seed(cfg)
    masked, mapping = masker.mask(req.logs, req.categories, terms,
                                  store.get_patterns(), base, floors, keep_terms=store.get_keep_terms())
    system = build_system(cfg, req.use_system, req.instructions, req.structured)
    used = _used_mapping(mapping, masked)
    if _vault_on(cfg) and req.vault_context:
        system += _vault_context_block(vault.context_lines(used.keys()))
    return {"system": system, "user": masked, "masked_count": len(used)}


@app.post("/convert_xlsx")
async def convert_xlsx(file: UploadFile = File(...)):
    """Convert an uploaded spreadsheet (.xlsx/.xlsm) to CSV text so it can flow
    through the same masking pipeline. Parsing happens in this local process —
    the raw file never leaves the machine, exactly like pasted logs."""
    name = (file.filename or "").lower()
    if not name.endswith((".xlsx", ".xlsm")):
        raise HTTPException(400, "Only .xlsx / .xlsm spreadsheets can be converted.")
    try:
        import openpyxl
    except ImportError:
        raise HTTPException(
            500, "Excel support needs openpyxl. Run: pip install openpyxl")

    import io
    import csv
    import zipfile

    # An .xlsx is a zip archive, so it is a zip bomb waiting to happen: a few
    # hundred KB can expand to gigabytes of XML and take the process down. Read
    # with a hard cap, then refuse implausible expansion before openpyxl parses
    # anything.
    data = b""
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                413, f"Spreadsheets are limited to "
                     f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            expanded = sum(i.file_size for i in z.infolist())
    except zipfile.BadZipFile:
        raise HTTPException(400, "That file is not a readable .xlsx/.xlsm.")
    if expanded > MAX_EXPANDED_BYTES:
        raise HTTPException(
            413, f"Refusing to open a spreadsheet that expands to "
                 f"{expanded // (1024 * 1024)} MB.")
    if len(data) and expanded / max(len(data), 1) > MAX_EXPANSION_RATIO:
        raise HTTPException(400, "Refusing a spreadsheet with an implausible "
                                 "compression ratio (possible zip bomb).")

    try:
        wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    except Exception as e:
        raise HTTPException(400, f"Could not read the spreadsheet: {e}")

    out = io.StringIO()
    writer = csv.writer(out)
    sheets = wb.worksheets
    cells = 0
    deadline = time.time() + MAX_PARSE_SECONDS
    for idx, ws in enumerate(sheets):
        if len(sheets) > 1:
            out.write(f"# --- Sheet: {ws.title} ---\n")
        for row in ws.iter_rows(values_only=True):
            # Streaming parse: the guards have to live in the loop, because a
            # crafted sheet reports a small size and then yields forever.
            cells += len(row)
            if cells > MAX_CELLS:
                wb.close()
                raise HTTPException(
                    413, f"Spreadsheet has more than {MAX_CELLS:,} cells.")
            if time.time() > deadline:
                wb.close()
                raise HTTPException(
                    413, "Spreadsheet took too long to read; convert it to CSV "
                         "and paste that instead.")
            if all(c is None for c in row):
                continue   # skip fully-empty rows
            writer.writerow(["" if c is None else c for c in row])
        if idx < len(sheets) - 1:
            out.write("\n")
    wb.close()

    base = re.sub(r"\.(xlsx|xlsm)$", "", file.filename or "spreadsheet", flags=re.I)
    return {"csv": out.getvalue(), "filename": base + ".csv",
            "sheets": len(sheets), "name": file.filename}


# ---------------------------------------------------------------------------
# Conversations. Each "Analyze by AI" starts one; follow-up questions are sent
# with the full (masked) history so the AI keeps context. State lives only in
# this process's memory — ending the conversation (or restarting the server)
# forgets it. The cumulative mapping keeps placeholders consistent across turns.
# ---------------------------------------------------------------------------
CONVERSATIONS: dict = {}

# Audit log of every outbound AI request (masked content only — that is the
# whole point). Each entry is appended to AI_REQUESTS_FILE as one JSON line,
# so there is a permanent on-disk audit trail to verify that no customer data
# ever left the machine. The in-memory deque feeds the Requests tab.
AI_REQUESTS_FILE = usage.LOG_FILE
REQUEST_LOG: deque = deque(maxlen=200)
_REQUEST_SEQ = {"n": 0}


def _log_request(kind: str, provider: str, model: str, system: str,
                 messages: list, response: str, error: str,
                 duration_ms: int, conversation_id: Optional[str],
                 leak_info: Optional[dict] = None,
                 token_usage: Optional[dict] = None) -> None:
    _REQUEST_SEQ["n"] += 1
    entry = {
        "seq": _REQUEST_SEQ["n"],
        # ISO-8601 with the UTC offset. An audit trail read on another machine,
        # in another timezone, or after a DST change has to be unambiguous —
        # a bare local "14:05" is not evidence of anything.
        "time": datetime.now().astimezone().isoformat(timespec="seconds"),
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
    if token_usage:
        # Token counts as billed by the provider. The credit view prefers
        # these over its own character-based estimate.
        entry["usage"] = token_usage
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
    token_usage = {}
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
        if not api_key and providers.needs_key(provider):
            label = providers.PROVIDERS.get(provider, {}).get("label", provider)
            raise HTTPException(
                400, f"No API key configured for {label}. Open Setup to add one.")
        try:
            response = providers.call(provider, api_key or "", model, system,
                                      messages, cfg, usage_out=token_usage)
        except providers.ProviderError as e:
            raise HTTPException(502, str(e))
        return response
    except HTTPException as e:
        error = str(e.detail)
        raise
    finally:
        _log_request(kind, provider, model, system, messages, response, error,
                     int((time.time() - start) * 1000), conversation_id,
                     leak_info, token_usage or None)


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


# ---------------------------------------------------------------------------
# Credit / spend dashboard
# ---------------------------------------------------------------------------
# Worth being explicit about what this can and cannot know: no provider we
# support exposes a remaining-balance endpoint to a normal API key, so there is
# nothing to fetch. What the app *can* do is price its own traffic — every call
# it makes is already in the audit log, with the provider's own token counts
# since usage capture landed. Requests made from anywhere else on the same key
# are invisible here, hence the "check balance" link on every card.
_EMPTY_TOTALS = {"requests": 0, "input_tokens": 0, "output_tokens": 0,
                 "cost": 0.0, "estimated_requests": 0, "unpriced": []}


def _cost_model(provider: str) -> str:
    if not providers.needs_key(provider):
        return "free" if provider == "ollama" else "licensed"
    if provider == "m365copilot":
        return "licensed"
    return "metered"


def _credits_payload() -> dict:
    cfg = load_config()
    data = usage.summary()
    registry = providers.public_registry()
    out = []
    for pid, meta in registry.items():
        stats = data["providers"].get(pid) or {}
        out.append({
            "provider": pid,
            "label": meta["label"],
            "billing_url": meta.get("billing_url", ""),
            "cost_model": _cost_model(pid),
            "model": resolve_model(cfg, pid),
            "month": stats.get("month") or _EMPTY_TOTALS,
            "all_time": stats.get("all_time") or _EMPTY_TOTALS,
        })
    return {
        "currency": data["currency"],
        "month": data["month"],
        "active_provider": cfg.get("provider", ""),
        "providers": out,
        "rates": pricing.table(),
        "log_file": data["log_file"],
    }


@app.get("/credits")
def get_credits():
    """Spend per provider, and what is left of the credit entered for it."""
    return _credits_payload()


@app.post("/credits/rate")
def set_credit_rate(req: RateRequest):
    """Pin the USD-per-1M-token rate for a model. Needed for Azure deployments
    and any model whose family we do not recognise; also the way to correct a
    seeded list price that no longer matches your bill."""
    try:
        pricing.set_rate(req.model, req.input_per_m, req.output_per_m)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _credits_payload()


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    """Mask the logs, send them to the AI, and start a conversation that
    follow-up questions (/chat) can continue."""
    cfg = load_config()
    provider = cfg["provider"]
    model = ("microsoft-365-copilot" if provider == "m365copilot"
             else resolve_model(cfg, provider))

    # 1. Mask locally with the saved dictionary. When the entity vault is on,
    #    it seeds the mapping so placeholders are stable across ALL incidents
    #    (a value seen last week keeps last week's placeholder) and numbering
    #    continues globally instead of restarting at _1.
    vault_on = _vault_on(cfg)
    terms = _merged_terms(req.custom_terms)
    base, floors = _vault_seed(cfg)
    masked, mapping = masker.mask(req.logs, req.categories, terms,
                                  store.get_patterns(), base, floors, keep_terms=store.get_keep_terms())
    used = _used_mapping(mapping, masked)   # entities of THIS log only

    # 2. Pre-send leak guard: independent second pass over the MASKED text.
    #    Blocking findings stop everything here — nothing has left the machine
    #    and no conversation exists — until the analyst acknowledges.
    warnings = leakguard.scan(masked, mapping, terms, req.categories,
                             keep_terms=store.get_keep_terms())
    if leakguard.has_blocking(warnings) and not req.acknowledge_leaks:
        return {"blocked": True, "warnings": warnings,
                "masked_count": len(used)}
    leak_info = ({"warnings": warnings, "acknowledged": req.acknowledge_leaks}
                 if warnings else None)

    # 3. Build the prompt and call the provider with ONLY the masked text.
    #    The system prompt is optional — the analyst can turn it off per run.
    system = build_system(cfg, req.use_system, req.instructions, req.structured)
    vault_lines = []
    if vault_on and req.vault_context:
        # History of the entities that recur from earlier incidents —
        # placeholder statistics only, gathered BEFORE this incident is
        # recorded so "prior" means prior.
        vault_lines = vault.context_lines(used.keys())
        system += _vault_context_block(vault_lines)

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
        "structured": req.structured, "vault_on": vault_on,
    }

    # 5. Restore real values locally (prose + structured verdict).
    shaped = _shape_response(raw_response, mapping, req.structured)

    # 6. Record this incident in the vault: its entities become part of the
    #    permanent cross-incident memory, and the AI's verdict is attached so
    #    future context can say "verdicts: true_positive ×2".
    if vault_on:
        vault.record(conv_id, used)
        v = shaped.get("verdict")
        if v:
            vault.set_verdict(conv_id, v.get("verdict"), v.get("severity"))

    return {
        "provider": provider,
        "model": model,
        "conversation_id": conv_id,
        "transcript": messages,               # masked history (what left/leaves)
        "masked_sent": masked,                # what actually left the machine
        "mapping": used,                      # placeholder -> real (local only)
        "masked_count": len(used),
        "warnings": warnings,                 # leak-guard findings (if any)
        "vault": {"enabled": vault_on,        # cross-incident context attached
                  "recurring": len(vault_lines),
                  "context": vault_lines},
        # What this conversation has cost so far (this one call, for now).
        "cost": usage.conversation(conv_id),
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
                                 "restarted). Analyze a log to start a new one.")
    question = req.question.strip()
    if not question:
        raise HTTPException(400, "The question is empty.")

    # Base for re-masking: the conversation's cumulative mapping, topped up
    # with the current vault state — another conversation may have added
    # entities (and advanced the numbering) since this one started, and a new
    # value here must not collide with their placeholders.
    base = conv["mapping"]
    floors = None
    if conv.get("vault_on"):
        base = {**vault.mapping(), **conv["mapping"]}
        floors = vault.counters()
    masked_q, mapping = masker.mask(question, conv["categories"],
                                    conv["custom_terms"],
                                    store.get_patterns(),
                                    base, floors, keep_terms=store.get_keep_terms())
    # Pre-send leak guard on the masked question (an analyst can paste raw
    # log content into a follow-up too). Nothing is appended or sent while
    # blocked.
    warnings = leakguard.scan(masked_q, mapping, conv["custom_terms"],
                              conv["categories"],
                             keep_terms=store.get_keep_terms())
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

    # The conversation's own entities: placeholders that occur anywhere in the
    # masked transcript (the cumulative mapping also carries the whole vault).
    used = _used_mapping(mapping, *(m["content"] for m in conv["messages"]))

    # A follow-up can introduce new entities (or a changed verdict) — keep the
    # vault's incident record for this conversation up to date.
    if conv.get("vault_on"):
        vault.record(req.conversation_id,
                     _used_mapping(mapping, masked_q))
        v = shaped.get("verdict")
        if v:
            vault.set_verdict(req.conversation_id,
                              v.get("verdict"), v.get("severity"))

    return {
        "provider": conv["provider"],
        "model": conv["model"],
        "conversation_id": req.conversation_id,
        "transcript": conv["messages"],
        "masked_question": masked_q,
        "mapping": used,
        "masked_count": len(used),
        # Running total for the conversation: the opening analysis plus every
        # follow-up so far, this one included.
        "cost": usage.conversation(req.conversation_id),
        **shaped,                             # restored prose + (updated) verdict
    }


@app.post("/chat/end")
def chat_end(req: EndConversationRequest):
    """Forget a conversation (history + mapping), freeing the UI for a new log.
    Returns its final cost: everything billed under this conversation id from
    the opening analysis to this moment."""
    CONVERSATIONS.pop(req.conversation_id, None)
    return {"ok": True, "cost": usage.conversation(req.conversation_id)}


@app.get("/healthz")
def healthz():
    """Liveness + where this instance keeps its state. The CLI uses `pid` to
    make sure it is talking to (and stopping) the server it started, rather
    than whatever else happens to hold the port."""
    return {
        "ok": True,
        "app": "log-masker",
        "version": VERSION,
        "pid": os.getpid(),
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "secret_backend": keystore.backend(),
        **paths.describe(),
    }


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
