# Log Masker — Safe AI Log Analysis

A local web app that lets you send raw logs to a public AI for security analysis
**without leaking customer data**. Sensitive values (usernames, emails, domains,
hostnames, IPs, MAC addresses, API keys, tokens, UUIDs, account numbers…) are
masked **locally** before anything leaves your machine. The AI analyses the
masked logs, and the real values are restored **locally** in the response.

## Supported AI providers

Choose one in **⚙ Setup** (provider + model + API key):

| Provider | API | Notes |
|----------|-----|-------|
| **Claude (Anthropic)** | api.anthropic.com | API key. Opus 4.8 / Sonnet 4.6 / Haiku 4.5 |
| **ChatGPT (OpenAI)** | api.openai.com | API key. gpt-5.5, gpt-5.5-pro, gpt-5.4(-mini/-nano) |
| **Gemini (Google)** | generativelanguage.googleapis.com | API key. gemini-3.5-flash, 3.1-pro, 3.1-flash-lite, 2.5-pro |
| **Microsoft 365 Copilot** | Microsoft Graph (`/beta/copilot`) | **OAuth sign-in** + Copilot license + Entra app (see below) |
| **Microsoft Copilot (Azure OpenAI)** | your Azure resource | API key + endpoint + deployment + api-version |

### Microsoft 365 Copilot (OAuth)

This is **not** an API-key provider. It uses the Microsoft 365 Copilot **Chat
API** (Microsoft Graph, currently preview `/beta`), which requires **delegated
sign-in** as a licensed user — app-only auth is not supported. Answers are
grounded in your tenant data and stay inside the Microsoft 365 trust boundary.

**One-time setup (you do this in Entra):**

1. In the [Entra admin center](https://entra.microsoft.com/) → **App registrations**
   → **New registration**. Give it a name; supported account type "Accounts in
   this organizational directory only" is fine.
2. Under **Authentication** → **Add a platform** → **Web**, add the **Redirect
   URI** shown in the app's Setup panel (e.g. `http://localhost:8000/oauth/callback`).
   *(If you run on a different port, register that exact URI.)*
3. Under **API permissions** → **Add a permission** → **Microsoft Graph** →
   **Delegated permissions**, add **all** of: `Sites.Read.All`, `Mail.Read`,
   `People.Read.All`, `OnlineMeetingTranscript.Read.All`, `Chat.Read`,
   `ChannelMessage.Read.All`, `ExternalItem.Read.All`. Grant admin consent if
   required by your org.
4. Copy the **Directory (tenant) ID** and **Application (client) ID** from the
   app's Overview page.
5. In Log Masker → **⚙ Setup** → **Microsoft 365 Copilot**: paste the tenant and
   client IDs, click **Save**, then **🔐 Sign in with Microsoft**.

No client secret is needed (public client + PKCE). Tokens are cached locally in
`m365_token_cache.json` (git-ignored).

> The Azure OpenAI option ("Microsoft Copilot (Azure OpenAI)") is the simpler,
> key-based path if you don't specifically need M365 Copilot's tenant grounding.

API keys are stored in your **OS keychain** (via `keyring`), never in the
browser or in any file. Non-secret settings (default provider, per-provider
default model, Azure endpoint) live in a local `app_config.json` (git-ignored).
**Test connection** in Setup sends a one-word ping to verify the key/model work.

**Default provider & model:** Setup lets you pick a default provider (★) and a
default model **per provider**, saved the moment you change them. The model
dropdown is populated **live from each provider's own catalog API** using your
key (click ↻ to refresh, or it auto-loads), so it never goes stale — and a
**Custom…** option lets you type any model ID. For Azure, the model is your
deployment name.

```
raw logs ──► [ local mask ] ──► masked logs ──► AI provider
                  │                                   │
            mapping stays local                  AI analysis
                  │                                   │
final result ◄── [ local un-mask ] ◄── masked AI response
```

The placeholder → real-value mapping **never leaves the server process**. Only
the masked text is sent to the Claude API.

## What gets masked

Toggle these categories in the UI:

- **Identities** — emails, `user=`/`username=`/`login=` values, `DOMAIN\user`.
- **Network** — FQDNs/hostnames, IPv4, IPv6, MAC addresses.
- **Secrets / IDs** — API keys (Anthropic/OpenAI/AWS/GitHub/Slack/Google),
  `password=`/`token=`/`secret=` values, UUIDs, long hashes, credit-card-like
  numbers.

Each unique real value maps to a stable placeholder (`[EMAIL_1]`, `[IP_3]`, …),
so the same value reads consistently to the AI.

> Masking is regex-based and best-effort. Use the **Preview masking** button to
> review exactly what will be sent before you send it.

## Setup

```bash
cd log_masker_app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Provider + API key

Open **⚙ Setup**, pick a provider, enter its API key, choose a model, and click
**Save**. The key is checked in this order:

1. OS keychain (saved via Setup).
2. Environment variable: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`,
   or `AZURE_OPENAI_API_KEY`.

Use **Test connection** to verify before analysing. Setup also lets you delete a
saved key per provider.

## Run

```bash
cd log_masker_app
./run.sh start              # background on a random free port; ./run.sh url to get it
# or, for development:
uvicorn app:app --reload --port 8000   # then open http://127.0.0.1:8000
```

## Workflow

1. Paste raw logs, pick which categories to mask, pick a model.
2. Click **Preview masking** to see the exact masked text + the local mapping.
3. Click **Mask & Analyse** to send the masked logs to Claude.
4. Read the **Final (restored)** tab — restored values are highlighted. The
   **Sent to AI** tab shows precisely what left your machine.

## Tests

```bash
python test_masker.py
```
