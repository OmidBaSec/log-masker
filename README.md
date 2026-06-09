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
| **Claude (Anthropic)** | api.anthropic.com | Opus 4.8 / Sonnet 4.6 / Haiku 4.5 |
| **ChatGPT (OpenAI)** | api.openai.com | gpt-4o, gpt-4o-mini, o1, … |
| **Gemini (Google)** | generativelanguage.googleapis.com | gemini-2.5-pro/flash, 2.0-flash |
| **Microsoft Copilot (Azure OpenAI)** | your Azure resource | needs endpoint + deployment + api-version |

> Microsoft has no public consumer-Copilot API — the "Copilot" option uses the
> **Azure OpenAI Service** that backs it. Create a resource and a model
> deployment in the Azure portal, then enter the endpoint, deployment name, and
> API version in Setup.

API keys are stored in your **OS keychain** (via `keyring`), never in the
browser or in any file. Non-secret settings (selected provider, model, Azure
endpoint) live in a local `app_config.json` (git-ignored). **Test connection**
in Setup sends a one-word ping to verify the key/model work.

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
