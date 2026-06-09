# Log Masker — Safe AI Log Analysis

A local web app that lets you send raw logs to Claude for security analysis
**without leaking customer data**. Sensitive values (usernames, emails, domains,
hostnames, IPs, MAC addresses, API keys, tokens, UUIDs, account numbers…) are
masked **locally** before anything leaves your machine. Claude analyses the
masked logs, and the real values are restored **locally** in the response.

```
raw logs ──► [ local mask ] ──► masked logs ──► Claude API
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

### API key

Provide your Anthropic API key one of three ways (checked in this order):

1. Paste it in **⚙ Settings** → stored in the OS keychain via `keyring`.
2. `export ANTHROPIC_API_KEY=sk-ant-...`
3. (Settings UI also lets you delete the saved key.)

## Run

```bash
uvicorn app:app --reload --port 8000
# then open http://127.0.0.1:8000
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
