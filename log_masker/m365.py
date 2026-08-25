"""
Microsoft 365 Copilot Chat API integration (delegated OAuth2 via MSAL).

Unlike the API-key providers, M365 Copilot requires a signed-in user (delegated
auth) with a Microsoft 365 Copilot license, and an Entra ID app registration.
App-only auth is NOT supported by the Copilot Chat API.

Flow implemented here (authorization code + PKCE, public client):
  1. /m365/login    -> redirect the browser to Microsoft sign-in.
  2. /oauth/callback -> exchange the code for tokens, cache them.
  3. chat()         -> silently acquire a token, then call the Chat API:
                         POST /beta/copilot/conversations           (create)
                         POST /beta/copilot/conversations/{id}/chat  (prompt)

Tokens are cached locally in m365_token_cache.json (git-ignored). Only the
masked prompt text is ever sent to Microsoft Graph.
"""

import os
import re
import json
import requests
from typing import Dict, Optional, Tuple

import msal

from log_masker import paths

CACHE_FILE = paths.data_file("m365_token_cache.json")

GRAPH = "https://graph.microsoft.com/beta"

# All of these delegated permissions are required by the Copilot Chat API.
SCOPES = [
    "Sites.Read.All",
    "Mail.Read",
    "People.Read.All",
    "OnlineMeetingTranscript.Read.All",
    "Chat.Read",
    "ChannelMessage.Read.All",
    "ExternalItem.Read.All",
]

DEFAULT_TZ = "America/New_York"

# In-memory store of in-flight auth code flows, keyed by OAuth `state`.
_FLOWS: Dict[str, dict] = {}


class M365Error(Exception):
    pass


# ---------------------------------------------------------------------------
# Token cache + MSAL app
# ---------------------------------------------------------------------------
def _load_cache() -> msal.SerializableTokenCache:
    cache = msal.SerializableTokenCache()
    if os.path.exists(CACHE_FILE):
        try:
            cache.deserialize(open(CACHE_FILE, "r", encoding="utf-8").read())
        except Exception:
            pass
    return cache


def _save_cache(cache: msal.SerializableTokenCache) -> None:
    if cache.has_state_changed:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            f.write(cache.serialize())
        try:
            os.chmod(CACHE_FILE, 0o600)
        except Exception:
            pass


def _app(tenant_id: str, client_id: str, cache) -> msal.PublicClientApplication:
    if not tenant_id or not client_id:
        raise M365Error("Set the Entra tenant ID and client ID in Setup first.")
    return msal.PublicClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        token_cache=cache,
    )


# ---------------------------------------------------------------------------
# Auth flow
# ---------------------------------------------------------------------------
def build_login_url(tenant_id: str, client_id: str, redirect_uri: str) -> str:
    try:
        cache = _load_cache()
        app = _app(tenant_id, client_id, cache)
        flow = app.initiate_auth_code_flow(SCOPES, redirect_uri=redirect_uri)
    except M365Error:
        raise
    except Exception as e:
        # e.g. invalid tenant -> MSAL raises ValueError during authority lookup.
        raise M365Error(f"Could not start sign-in (check tenant/client IDs): {e}")
    if "auth_uri" not in flow:
        raise M365Error(f"Could not start sign-in: {flow}")
    _FLOWS[flow["state"]] = flow
    return flow["auth_uri"]


def handle_callback(query: dict, tenant_id: str, client_id: str) -> str:
    """Exchange the authorization code for tokens. Returns the signed-in UPN."""
    state = query.get("state")
    flow = _FLOWS.pop(state, None)
    if not flow:
        raise M365Error("Sign-in session expired or unknown. Try again.")
    cache = _load_cache()
    app = _app(tenant_id, client_id, cache)
    result = app.acquire_token_by_auth_code_flow(flow, query)
    if "access_token" not in result:
        raise M365Error(result.get("error_description")
                        or result.get("error") or "Token exchange failed.")
    _save_cache(cache)
    return (result.get("id_token_claims", {}) or {}).get("preferred_username", "")


def status(tenant_id: str, client_id: str) -> Tuple[bool, str]:
    """Cheap, network-free sign-in check: read the token cache file directly.

    Building an MSAL app would trigger a network authority lookup on every
    call, so we just inspect the cached Account entries instead."""
    if not tenant_id or not client_id or not os.path.exists(CACHE_FILE):
        return False, ""
    try:
        data = json.load(open(CACHE_FILE, "r", encoding="utf-8"))
        for acc in (data.get("Account") or {}).values():
            return True, acc.get("username", "")
    except Exception:
        pass
    return False, ""


def logout(tenant_id: str, client_id: str) -> None:
    """Sign out by clearing the local token cache (no network)."""
    try:
        os.remove(CACHE_FILE)
    except FileNotFoundError:
        pass
    except Exception:
        pass


def _token(tenant_id: str, client_id: str) -> str:
    cache = _load_cache()
    app = _app(tenant_id, client_id, cache)
    accounts = app.get_accounts()
    if not accounts:
        raise M365Error("Not signed in. Open Setup and sign in with Microsoft.")
    result = app.acquire_token_silent(SCOPES, account=accounts[0])
    _save_cache(cache)
    if not result or "access_token" not in result:
        raise M365Error("Session expired. Please sign in again.")
    return result["access_token"]


# ---------------------------------------------------------------------------
# Copilot Chat API
# ---------------------------------------------------------------------------
_TAG_RE = re.compile(r"</?(?:Person|Event|File|Email|Phone|Time)>")
_FOOTNOTE_RE = re.compile(r"\[\^\d+\^\]")


def _clean(text: str) -> str:
    """Strip Copilot's annotation tags and footnote markers for plain output."""
    text = _TAG_RE.sub("", text)
    text = _FOOTNOTE_RE.sub("", text)
    return text.strip()


def chat(tenant_id: str, client_id: str, system: str, user_text: str,
         web_enabled: bool = False, timezone: str = DEFAULT_TZ) -> str:
    """Create a conversation and send one prompt; return the assistant text."""
    token = _token(tenant_id, client_id)
    headers = {"Authorization": f"Bearer {token}",
               "Content-Type": "application/json"}

    # 1. Create a conversation.
    r = requests.post(f"{GRAPH}/copilot/conversations", headers=headers,
                      data="{}", timeout=60)
    if r.status_code not in (200, 201):
        raise M365Error(f"Create conversation failed {r.status_code}: "
                        f"{r.text[:400]}")
    conv_id = r.json().get("id")
    if not conv_id:
        raise M365Error("No conversation id returned.")

    # 2. Send the prompt. Copilot has no system role, so prepend instructions.
    prompt = f"{system}\n\n--- LOGS TO ANALYSE ---\n{user_text}"
    body = {
        "message": {"text": prompt},
        "locationHint": {"timeZone": timezone},
        "contextualResources": {"webContext": {"isWebEnabled": bool(web_enabled)}},
    }
    r = requests.post(f"{GRAPH}/copilot/conversations/{conv_id}/chat",
                      headers=headers, data=json.dumps(body), timeout=120)
    if r.status_code != 200:
        raise M365Error(f"Chat failed {r.status_code}: {r.text[:400]}")

    messages = r.json().get("messages", [])
    if not messages:
        raise M365Error("No messages in Copilot response.")
    # The assistant's answer is the last message (first is the echoed prompt).
    return _clean(messages[-1].get("text", ""))
