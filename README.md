# Log Masker — safe AI log analysis

**Get an AI to analyse your logs without handing it your customers' data.**
Sensitive values are replaced with placeholders on your own machine before
anything is sent, and the real values are put back locally in the answer.

```
  2026-06-09 sshd: Failed password for jsmith from 203.0.113.47
                              │
                              │  masked locally — this is what leaves
                              ▼
  2026-06-09 sshd: Failed password for [USER_3] from [IP_1]
                              │
                              │  the AI answers about placeholders
                              ▼
  "[IP_1] made 6 failed attempts against [USER_3] before succeeding…"
                              │
                              │  restored locally — this is what you read
                              ▼
  "203.0.113.47 made 6 failed attempts against jsmith before succeeding…"
```

The attack pattern survives; the identities do not. Works with Claude, ChatGPT,
Gemini, Azure OpenAI, M365 Copilot, or a local model via Ollama — where even the
masked text stays on your hardware.

[![CI](https://github.com/OmidBaSec/log-masker/actions/workflows/ci.yml/badge.svg)](https://github.com/OmidBaSec/log-masker/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

## Try it in 30 seconds — no API key needed

```bash
git clone https://github.com/OmidBaSec/log-masker.git
cd log-masker
python3 -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.lock
python -m log_masker.cli start --open
```

Paste [`sample_logs/ssh-brute-force.log`](sample_logs/) into the workspace and
press **Preview masking**. No provider is contacted, no key is required, and the
*Masked data* tab shows you exactly what would have been sent. Only when you
press **Mask & Analyse** does anything leave the machine — and only the masked
text.

## What this tool does and does not guarantee

Read this before pointing it at production logs.

Masking is **pattern-based and best-effort**. It recognises the categories
listed below plus the terms and regexes you add, and it is tested hard (see
[Tests](#tests) — 589 checks, most of them masking cases). It cannot recognise
what it has never been taught: an internal codename, an unusual identifier
format, a customer name written in a way no rule matches. The **pre-send leak
guard** is an independent second pass that catches many such misses, and the
masked text is shown to you in full before anything is sent — but neither is a
guarantee.

Concretely:

* **You are responsible for what leaves your machine.** Review the *Masked
  data* tab before sending. That is why it exists.
* **The audit log records what was sent**, in masked form. It is evidence of
  the content of each request — it is not proof that no sensitive data was ever
  transmitted.
* **The AI provider still receives your logs**, structurally intact. Placeholder
  patterns, timestamps, event sequences and volumes can themselves be
  informative. If your policy forbids sending any operational data to a third
  party, use the local-model (Ollama) provider, which never leaves the machine.
* **Cost figures are local estimates**, priced from published list rates that
  drift. Your provider's bill is the authority.
* **No warranty of any kind.** Use it on data you are authorised to handle.

If you find a masking gap, please report it — a failing sample log makes an
excellent bug report and usually becomes a new test case.

## Supported AI providers

Choose one in **⚙ Setup** (provider + model + API key):

| Provider | API | Notes |
|----------|-----|-------|
| **Claude (Anthropic)** | api.anthropic.com | API key. Opus 4.8 / Sonnet 4.6 / Haiku 4.5 |
| **ChatGPT (OpenAI)** | api.openai.com | API key. gpt-5.5, gpt-5.5-pro, gpt-5.4(-mini/-nano) |
| **Gemini (Google)** | generativelanguage.googleapis.com | API key. gemini-3.5-flash, 3.1-pro, 3.1-flash-lite, 2.5-pro |
| **Microsoft 365 Copilot** | Microsoft Graph (`/beta/copilot`) | **OAuth sign-in** + Copilot license + Entra app (see below) |
| **Microsoft Copilot (Azure OpenAI)** | your Azure resource | API key + endpoint + deployment + api-version |
| **Local model (Ollama)** | `http://127.0.0.1:11434` (configurable) | **No key, fully local** — for logs that must not reach any cloud, even masked |

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

### Local model (Ollama) — for restricted logs

Masking makes cloud analysis safe for most logs, but some log classes must not
leave the machine **even masked** (classified environments, contractual
restrictions, air-gapped sites). The Ollama provider covers that tier: the
model runs on this machine, so the entire pipeline — masking, analysis,
restore — is local end to end. Everything else works identically: templates,
structured verdicts, conversations, leak guard, audit log, entity vault.

Setup: [install Ollama](https://ollama.com/download), pull a model
(`ollama pull llama3.1`), then pick **Local model (Ollama)** in ⚙ Setup — no
API key. The model dropdown lists whatever your Ollama instance has pulled
(live from its `/api/tags`); the endpoint is configurable for a shared
inference box on your network (default `http://127.0.0.1:11434`). The provider
card shows **✓ reachable / offline** instead of key status. Local inference
gets a 10-minute request timeout — big models on CPU are slow.

> Small local models write noticeably weaker analyses than the cloud models.
> Prefer the largest model your hardware can run (e.g. `llama3.1:70b` >
> `llama3.1:8b`) for anything beyond a quick triage.

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

Every analysis masks all three categories:

- **Identities** — emails, `user=`/`username=`/`login=` values, `DOMAIN\user`,
  Windows SIDs (`S-1-5-21-…`), Active Directory distinguished names
  (`CN=…,OU=…,DC=…`), international phone numbers (`+49 …`), group, role, zone
  and policy names (`[GROUP_1]`), departments, organisation and tenant names
  (`[ORG_1]`), and meeting topics (`[SUBJECT_1]`).
- **Network** — FQDNs/hostnames, IPv4, IPv6, MAC addresses, syslog header
  hostnames, `devname=`/`devid=` device names, and the cloud estate: AWS ARNs
  as a single token (`[ARN_1]`), `"resourceId"`/`"resourceName"` paths, plus
  the buckets, repos, projects, environments and document paths of cloud and
  SaaS logs (`[ASSET_1]`).
- **Secrets / IDs** — API keys (Anthropic/OpenAI/AWS/GitHub/Slack/Google),
  `password=`/`token=`/`secret=`/`community=` values, UUIDs, long hashes,
  credit-card-like numbers, cloud account and tenant numbers (`[ACCTID_1]`),
  and vendor principal / object ids — IAM `AIDA…`/`ASIA…`, Okta `00u…`, Duo
  integration keys, 24-character Atlassian ids (`[KEYID_1]`).

Field-aware extraction understands common raw log formats out of the box —
just paste and the preview updates automatically:

- **Windows Event Logs** (4624/4625/4720…) — indented `Account Name:`,
  `Account Domain:`, `Workstation Name:`, `Security ID:`, `Caller Computer
  Name:` … fields are extracted and their values masked, while the field labels
  and built-in accounts (`SYSTEM`, `NT AUTHORITY`, `-`) stay readable so the AI
  still understands the structure.
- **Network devices** (Cisco ASA/IOS, FortiGate, generic syslog) — the syslog
  header hostname, `user 'x'`, `user="x"`, `devname="x"`, `srcip=`/`dstip=`,
  SNMP community strings.
- **Sysmon** (text and XML) — `User: DOMAIN\user`, `ParentUser:`, usernames in
  profile paths (`C:\Users\j.doe\…`, `/home/j.doe/…` — only the name is masked,
  the path stays readable), `<Data Name='TargetUserName'>`, `<Computer>`,
  hashes. System paths (`C:\Windows\System32\…`) and built-in accounts
  (`NT AUTHORITY\SYSTEM`) are left intact for the AI.
- **QRadar** — LEEF events (`usrName=`, `src=`/`dst=`, `identHostName=`),
  offense API exports (`"offense_source":`, `"assigned_to":`), and event-viewer
  copies (`Username:`, `Source IP:`, `Log Source:` hostnames). The same value
  gets the same placeholder across all three formats.
- **Linux OS** — sshd (`Failed password for invalid user X from`, `Accepted
  publickey for X`), sudo (`sudo: X :`, working-directory `PWD=/home/X`),
  su/pam session lines (`for user X by Y(uid=…)`). `root` and numeric uids
  stay readable.
- **Cloud / Microsoft JSON** (Azure Platform, Entra ID sign-ins, Microsoft 365
  Defender, Defender for Cloud, Office 365) — `"userPrincipalName"`,
  `"userDisplayName"`, `"AccountName"`, `"AccountDomain"`, `"DeviceName"`,
  `"compromisedEntity"`, `"password"`, `"ipAddress"`; quoted JSON keys are
  understood everywhere (`"user":"x"` works like `user=x`).
- **AWS** (CloudTrail, Config, S3 server access, Security Hub) — ARNs are
  masked as one token, so the account number and the principal never split
  across two placeholders; 12-digit account ids under any `…AccountId` key;
  IAM principal ids and temporary STS keys (`AIDA…`, `AROA…`, `ASIA…`);
  EC2/EBS resource ids (`i-0abc…`); and the bucket name plus object key of the
  positional S3 access log. The vendor's own product ARN
  (`arn:aws:securityhub:…::product/aws/guardduty`) carries no account number
  and stays readable.
- **Identity providers** (Okta, OneLogin, Duo Security, JumpCloud, Entra ID) —
  Okta object ids (`00u…`, `0oa…`), Duo integration keys, 24-character
  Atlassian/JumpCloud object ids, numeric `"user_id"` values, actor objects
  (`"user":{"name":…}`), `"alternateId"` and `"department"`. Multi-word values
  are taken whole, so `"displayName":"John Smith"` becomes one placeholder
  instead of a masked first name and a visible surname.
- **SaaS audit logs** (GitHub, Atlassian Jira, Zoom, DocuSign, Dynamics 365,
  Power Platform) — actor keys (`"actor"`, `"authorKey"`, `"operator"`,
  `"createdBy"`), organisation / tenant / business names, repos, environments,
  group names inside `"objectItem":{"name":…}`, and meeting topics. Event
  taxonomy values (`"action":"repo.destroy"`) stay readable.
- **Cloud platforms** (GCP, Azure Storage, Office 365, Purview, Defender for
  Cloud Apps, M365 Defender) — `"resourceName"` paths, GCP project ids, and
  the container and document path inside blob, `s3` and SharePoint URLs (only
  the path is claimed, so the tenant hostname keeps one `[HOST_n]` alias
  everywhere it appears), Purview DLP policy names and detected values, and
  `rbacGroupName`.
- **Cloud-era appliances** (CylancePROTECT, Imperva WAF Gateway, Qualys VM,
  Infoblox NIOS, UniFi Security Gateway, pfSense, Symantec ProxySG, Cribl) —
  zone, group and policy names in both `Zone Names: (…)` and JSON form,
  self-describing CEF custom strings (`cs1Label=Policy cs1=…`, where the key
  alone tells a generic pattern nothing), and Qualys `<DNS>` / `<NETBIOS>`
  asset elements.
- **Firewalls & appliances** — Cisco Meraki (epoch-header device names,
  `identity='x'`), Cisco Firepower/IronPort, Check Point (`user: x;`,
  `src:`/`dst:`), Palo Alto CSV (`acme\user`), Sophos XG
  (`user_name=`/`device_name=`), Citrix NetScaler (`User x -`, `Context x@ip`),
  F5 BIG-IP APM (`Username 'x'`), McAfee Web Gateway (CEF `suser=`),
  SonicWALL SonicOS (`usr=`, device serials `sn=`), Barracuda WAF/CloudGen,
  McAfee Network Security Platform, Microsoft Azure Firewall (whole
  `"resourceId"` masked as one token), HP ProCurve / Aruba / Extreme
  Networks syslog.
- **Endpoint security** (Symantec Endpoint Protection, Trend Micro Deep
  Security / Deep Discovery, McAfee ePO, Cisco AMP, Sophos Central, Keeper) —
  space-separated keys (`Computer name:`, `User name:`, `Domain name:`), CEF
  `suser=`/`target=`/`shost=`/`dvchost=`, ePO XML (`<MachineName>`,
  `<UserName>`), JSON-escaped values (`"ACME\\user"`,
  `"C:\\Users\\x\\file"`); threat/risk names stay readable.
- **DNS & DHCP** (ISC BIND, Linux dhcpd) — queried domains, client IPs, and
  the hostname dhcpd reports in parens (`(WS-FIN-07) via eth0`).
- **QRadar internals** (SIM Audit, Custom Rule Engine, Anomaly Detection,
  Asset Profiler, Health Metrics, System Notification) — `user@ip` actor
  tokens and the generic QRadar/LEEF fields above.
- **Wazuh** — agent/manager names in alert JSON (`"agent":{"name":…}`),
  syslog alert headers (`(agent) ip->module`), quoted `Agent: "x"` lines,
  `srcuser=`/`dstuser=`, and hostnames inside the embedded `full_log` string
  (same placeholder as the JSON fields). Browser `User-Agent:` headers are
  deliberately not matched.
- **Squid Web Proxy** — the username/ident field of the native access log
  plus client IPs and requested domains; cache verdicts stay readable.
- **WatchGuard Fireware** — device serials after the syslog hostname,
  plus the usual syslog/IP fields. Trend Micro Apex Central and Veeam Decoy
  Server work via the CEF/syslog patterns above.
- **VMware** (EMC VMware / ESXi / vCenter) — ISO-timestamp syslog header
  hostnames, `User x@ip logged in`, dotted-domain logins
  (`ACME.LOCAL\user`), UNC server names (`\\fileserver\share`).
- **PowerShell** (transcripts, script-block logs / event 4104, pasted console
  sessions) — PowerShell hides its identifiers in three shapes no `key=value`
  pattern can reach, and all three are handled:
  * **Parameters**, which are separated from their argument by a *space* and
    may take a list — `-ComputerName WKS-01,WKS-02`, `-Credential CORP\svc`,
    `-Identity a.novak`, `-UserName`, `-SamAccountName`, `-Mailbox`,
    `-ResourceGroupName`. Each list item gets its own placeholder, so two
    machines never collapse into one. `-Name` and `-DisplayName` are read from
    the cmdlet on the line: a person in `New-ADUser`, a machine in `Get-AzVM`,
    and left alone in `Get-Service -DisplayName "Print Spooler"`.
  * **`Format-Table` output**, where the row of dashes gives the column
    boundaries and the header is the only clue to what a cell holds.
    `Get-LocalUser` and `Get-ADUser` tables are masked cell by cell;
    `Get-Service` and `Get-Process` tables are left alone.
  * **`-EncodedCommand`** base64 blobs — decoded locally, and masked only when
    the decoding holds something that would have been masked in the clear.
  Plaintext credentials are caught in the forms PowerShell writes them:
  `ConvertTo-SecureString 'literal'`, `-Password`, `-AccessToken`, `Bearer`
  tokens, SQL connection strings (`User ID=`/`Password=`), `az login -p`, and
  the positional password of `net use … /user:DOM\svc <password>` — while the
  cmdlet being invoked stays readable. Transcript headers (`Username:`,
  `Machine:`) and filenames (`PowerShell_transcript.WKS-01.…`), `Format-List`
  person fields (`DisplayName`, `GivenName`, `Surname`), AD attributes
  (`-GivenName`, `-Surname`, `-StreetAddress`), `Get-Credential "DOM\user"`,
  Azure resources (`-VaultName`, `-ResourceGroupName`) and Graph filters
  (`-Filter "displayName eq 'X'"`) are extracted too.
- **Mail & proxies** (Postfix, reverse proxies) — addresses in `from=<…>` /
  `to=<…>`, relay hosts, and the authuser field of Apache/nginx combined
  access logs.

Each unique real value maps to a stable placeholder (`[EMAIL_1]`, `[IP_3]`, …),
so the same value reads consistently to the AI — one placeholder per value,
even when two patterns disagree about whether it is a user or a host.

**Once a value is masked anywhere, it is masked everywhere in that paste.** A
pattern can only anchor on one shape of a name: a transcript header says
`Machine: WKS-01`, and two lines down `hostname` echoes a bare `WKS-01` that
nothing marks as anything. The masker takes a second pass for every value it
has already decided is sensitive, including the short form of an FQDN and the
domain half of `DOMAIN\user`.

An asset name is also picked up from prose when a keyword anchors it —
`logged into host WORKSTATION-88`, `connect to server SRV-DB-01` — since the
value has to look like an asset name for the match to count.

What no pattern can reach is a name with nothing around it at all: a bare
`SRV-SQL-03` in a `TrustedHosts` list, `Login on SRV-DC02` in a mail subject,
or a person's name inside a free-text description column. The [pre-send leak
guard](#pre-send-leak-guard) flags those as `host_like` warnings before
anything is sent, and **Custom terms** lets you pin your own asset names
permanently.

### Saved regex patterns (teach it once, reuse forever)

If a customer-specific value slips through, open **Saved regex patterns** in
the UI and add a label + regex (e.g. `TICKET` / `INC\d{7}`). Saved patterns are
stored locally in `custom_store.json` and applied automatically to **every**
log you paste from then on — no need to add them again. If the regex contains a
capture group, only the group is masked (`key=(value)` style); otherwise the
whole match is.

### Regex workbench — "why was this not masked?"

**🔬 Regex Workbench** in the sidebar. Paste the line a value slipped through
in, name the value, and press **Diagnose**. Everything runs on this machine:
the whole reason it exists is that a log too sensitive to hand an AI provider
is also too sensitive to paste into an online regex tester.

It answers the question in two halves. First, **why** the value survived —
there are four different reasons and they have four different fixes:

| Verdict | What it means | Where the fix is |
|---|---|---|
| No pattern matches this | nothing in the library sees these characters | a regex change |
| Matched, then dropped | a pattern found it and an accept rule threw it out — it names the rule, e.g. *"`.pdf` is on the not-a-TLD list"* | usually an allow-list, not a regex |
| Deliberately kept | a protected span claimed it (a file hash, a vendor id) | nothing — see [what is deliberately not masked](#what-is-deliberately-not-masked) |
| Claimed by a higher-priority pattern | something else masked those characters first | the competing pattern |
| Already masked | the current patterns handle it | nothing |

Then, for the cases a regex *does* fix, it proposes the change — preferring to
**widen the built-in that should have caught it** over adding a new pattern,
because one more field name in an existing list is a change a reviewer can
read. An indented `Requesting Workstation:` line is offered as an addition to
the Windows Event Log pattern, not to the generic `host=` one, and a
`-TargetBox` argument goes to the PowerShell parameter pattern.

Every proposal is **verified before it is offered**: applied at that pattern's
real priority, the value is gone from the sample. Proposals that only work
because they were tried at the top of the list are dropped, as are ones that
match somewhere other than where the value actually sits. Each card shows what
else it would newly mask in the sample, so an over-broad edit is visible before
it is saved. **Test** runs a candidate and lists every value it would mask —
including any the accept rules would then drop, and why. **Save** writes it
through the same validation as a hand-typed regex, into
`builtin_overrides.json` or the saved-patterns store.

### Editing the built-in regexes (per log source & field)

Open **⚙ Setup → 🧩 Edit masking regexes**. Every built-in pattern is listed,
grouped by log source type (Windows Event Log, Linux sshd, Cisco Meraki,
McAfee ePO XML, AWS CloudTrail, Okta, GitHub, …) with the field it extracts
(`[USER]`, `[HOST]`, `[SECRET]`, …). Edit a regex and press **Save** — the change applies to every
future paste and survives restarts (stored locally in
`builtin_overrides.json`). Patterns marked **modified** can be restored with
**↺ default**. A regex that doesn't compile is rejected on save; if an
override ever becomes invalid on disk, the default is used instead.

> Masking is regex-based and best-effort. Use the **Preview masking** button to
> review exactly what will be sent before you send it.

## Setup

**Requires Python 3.11 or newer.** Earlier versions cannot install the current,
patched releases of Starlette and python-multipart, so 3.9/3.10 would leave you
running known-vulnerable dependencies. Check with `python3 -V`.

<details open>
<summary><b>macOS / Linux</b></summary>

```bash
cd log_masker_app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock     # exact, resolved versions
```

Or install it as a command:

```bash
pip install .            # then: log-masker start --open
```
</details>

<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
cd log_masker_app
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.lock
```
</details>

No Python 3.11+ on the machine and no admin rights? [uv](https://docs.astral.sh/uv/)
installs one per-user, without touching the system Python:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh     # Windows: see the uv docs
uv python install 3.13
uv venv --python 3.13 --seed .venv
```

`requirements.txt` pins the direct dependencies; `requirements.lock` is the full
resolved set and is what CI installs.

### Provider + API key

Open **⚙ Setup**, pick a provider, enter its API key, choose a model, and click
**Save**. The key is checked in this order:

1. OS keychain (saved via Setup).
2. Environment variable: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`,
   or `AZURE_OPENAI_API_KEY`.

Use **Test connection** to verify before analysing. Setup also lets you delete a
saved key per provider.

## Run

The launcher is pure Python and behaves the same on macOS, Windows and Linux:

```bash
log-masker start --open           # if installed with pip
python -m log_masker.cli start    # from a checkout — same commands

log-masker status                 # version, data directory, secret backend
log-masker logs -f                # follow the server log
log-masker stop
log-masker where                  # where data and secrets live on this OS
```

Shell wrappers are provided for habit and for double-clicking — they all just
call `cli.py`:

| Platform | Wrapper |
|---|---|
| macOS / Linux | `./run.sh start` |
| Windows (PowerShell) | `.\run.ps1 start` |
| Windows (cmd) | `run.bat start` |

For development, run the server in the foreground:

```bash
uvicorn log_masker.app:app --reload --port 8000   # http://127.0.0.1:8000
```

**It only listens on `127.0.0.1`, and it refuses to start on any other
interface.** There is no login: anything that can reach the port can read the
entity vault and spend your API credit. To expose it deliberately, put an
authenticating proxy in front and set `LOGMASKER_ALLOW_REMOTE=1` plus
`LOGMASKER_ALLOWED_HOSTS=<your hostname>`.

### Docker

```bash
docker compose up -d                    # http://127.0.0.1:8888
docker compose --profile local up -d    # ...plus Ollama, for a fully local pipeline
```

The image runs as an unprivileged user with a read-only root filesystem and
keeps state in a named volume. A container has no OS keychain, so secrets go to
the encrypted-file tier — set `LOGMASKER_MASTER_KEY` from your secret manager so
the key never lands on the volume:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

The compose file publishes the port on `127.0.0.1` on purpose. **There is no
login.** To share an instance, put an authenticating proxy in front of it and
set `LOGMASKER_ALLOWED_HOSTS` to the hostname clients use.

### Where your data lives

`python cli.py where` prints it. The rules, in order:

1. `LOGMASKER_DATA_DIR`, if set (this is what Docker and portable installs use).
2. The application directory, if it already contains data — so an existing
   install is never relocated.
3. Otherwise the standard per-user location:
   `~/Library/Application Support/LogMasker` (macOS), `%APPDATA%\LogMasker`
   (Windows), `$XDG_DATA_HOME/logmasker` (Linux).

API keys and the vault key go to the OS keychain (macOS Keychain, Windows
Credential Manager, Freedesktop Secret Service). Where there is no keychain —
a container, a headless Linux box, SSH without a D-Bus session — they fall back
to an encrypted file in the data directory, whose master key comes from
`LOGMASKER_MASTER_KEY` if set, otherwise a `master.key` file created with
owner-only permissions. On a server, set `LOGMASKER_MASTER_KEY` from your secret
manager so the key never lands on disk.

## What is deliberately *not* masked

Security telemetry is full of values that look sensitive and identify nobody.
Masking them does not protect anyone — it just makes the alert unreadable and
the AI's answer useless — so these survive into the text that is sent:

* **File hashes** under an explicit hash key (`SHA256=`, `"sha1":`, `MD5=`,
  `imphash`). A hash is the IOC: it is the thing worth looking up, and it
  identifies a binary rather than a person. A bare `hash=` is *not* in this
  list — that is where credential dumps put NTLM hashes, and those are masked.
* **Vendor reference ids** — `detectorId`, `alertId`, `incidentId`, `ruleId`,
  `correlationId`. They identify the detection, not the detected.
* **ATT&CK technique and tactic ids** (`T1204`, `TA0006`).
* **Loopback and unspecified addresses** — `127.0.0.1`, `::1`, `0.0.0.0`. Every
  host is `127.0.0.1` to itself; masking it removes the fact that something was
  local.
* **Security-console hostnames** — `security.microsoft.com`, `portal.azure.com`,
  `graph.microsoft.com` and similar, matched exactly. Never by suffix:
  `contoso.sharepoint.com` names the tenant and is still masked.
* **API and schema namespaces** — `@odata.type`,
  `#microsoft.graph.security.deviceEvidence`, `event.kind`. A camelCase final
  label is not a TLD.
* **System paths and binaries** — `C:\Windows\System32\...`, `powershell.exe`.
* **Phishing evidence** — the `"subject"` line and the attachment `"filename"`
  of an email security alert (Proofpoint TAP). In a phishing case the lure *is*
  the question, exactly like a file hash. The recipient address is still masked.
* **Vendor product ARNs** — `arn:aws:securityhub:…::product/aws/guardduty` has
  no account number and names the detector. A customer ARN, which does carry an
  account number, is masked as one token.
* **Vendor application names** — `"appName":"Box"` names the SaaS vendor, not
  the customer; masking it removes the one fact an impossible-travel alert is
  about. A customer's own app, service or environment name is still masked.
* **Event taxonomies** — `"action":"repo.destroy"`,
  `"eventType":"user.session.start"`, `"eventSource":"signin.amazonaws.com"`.
  These dotted lowercase enums say *what happened*, and would otherwise be
  read as hostnames.
* **.NET type names, PowerShell variables and provider paths** —
  `[System.Net.Dns]`, `New-Object System.Management.Automation.PSCredential`,
  `$wc.Proxy`, `Microsoft.PowerShell.Core\FileSystem::`. They are dotted and
  backslashed like a hostname or a `DOMAIN\user` and name nothing but the
  runtime.
* **Built-in groups and services** — `Domain Admins`, `Authenticated Users`,
  `Print Spooler`, `Windows Update`.
* **Numbers that only look like cards** — a 13–16 digit run is masked as a
  credit card only if it passes the Luhn check digit, so a PowerShell
  transcript's `Start time: 20260902141233` stays readable.

Tenant ids, Entra device ids, EDR device ids, cloud account numbers, and
link-local addresses *are* masked: they identify the organisation or the
machine.

## Log file encodings

Uploaded logs are decoded from their actual bytes rather than assumed to be
UTF-8. Windows exports — Event Viewer, `Get-WinEvent | Out-File`, IIS — are
routinely **UTF-16 LE with a BOM and CRLF line endings**, and are detected by
their byte-order mark or, when a tool omits it, by their NUL pattern. UTF-16 BE
and UTF-8 with a BOM are handled too; the BOM character is stripped and CRLF
(and bare CR) are normalised to LF before masking. UTF-32 is refused with a
message rather than silently mangled. The detected encoding is shown in the
status line when it is not plain UTF-8.

## SOC analysis templates (MITRE ATT&CK)

A built-in library of analyst prompt templates covers the common attack
categories — brute force, suspicious logon, lateral movement, privilege
escalation, persistence, execution, defense evasion, discovery, C2/beaconing,
DNS tunneling, exfiltration, ransomware, account manipulation, web-app attack,
and phishing. Each is mapped to its **MITRE ATT&CK tactic + technique ID**
(e.g. Brute Force `T1110`, Remote Services `T1021`).

- **Searchable dropdown** — under **SOC analysis template** on the input panel,
  type to filter by name, category, tactic, technique, or ATT&CK id
  (`T1110`, `lateral`, `exfil`…). Selecting one fills the analysis
  instructions with a ready-made, expert prompt for that scenario.
- **Auto-suggestion** — when you paste a raw log, the app scores it locally
  against each template's indicators and shows the best matches as ⚡ chips;
  click one to apply it. Suggestion runs entirely on the local raw text —
  only template ids + scores are computed, no log content leaves the machine.
- **Edit & add** — **✏ Edit / add templates** opens an editor: change any
  template's prompt and MITRE mapping, create your own (with comma-separated
  *keywords* that drive its auto-suggestion), or delete custom ones. Built-in
  templates show a **modified** badge and restore with **↺ default**. Edits
  persist locally in `templates_store.json` and survive restarts.

## Workflow

1. Paste raw logs — or **📎 upload / drag & drop a log file** (text formats,
   up to 10 MB; it is read locally in the browser and never uploaded
   anywhere). Pick a model. Apply a SOC template
   (suggested ⚡ chip or the searchable dropdown) for a guided prompt.
   The masked version appears immediately in **Sent to AI**, where
   **⬇ Download masked** saves it as `<name>.masked.txt` for offline review
   before you submit anything.
2. Click **Preview masking** to see the exact masked text + the local mapping.
3. Click **Mask & Analyse** to send the masked logs to the AI. This starts a
   **conversation**: the result pane becomes a chat where you can ask
   follow-up questions and the AI keeps the context of all previous turns.
4. Restored values are highlighted in the chat. The **Sent to AI** tab shows
   the full masked transcript — precisely what left your machine.
5. Click **⏹ End conversation** to discard the AI-side history and the local
   mapping, then analyse the next raw log in a fresh conversation.

### Requests tab (audit log)

The **Requests** tab lists every request sent to an AI provider — analyses,
follow-ups, and connection tests — newest first. Each entry shows the
timestamp, provider/model, duration, success or the exact error, the system
prompt, every (masked) message that was sent, and the raw (masked) response.
Failed attempts are logged too.

Every entry is also **appended to a local audit file**, `ai_requests.jsonl`
(one JSON object per line, masked content only), so you can prove later that
no customer data ever left the machine — e.g.:

```bash
# anything that left the machine containing "ACME"? (should print nothing)
grep -i "acme" ai_requests.jsonl
```

The file is append-only: **Clear view** only empties the on-screen list, and
the most recent entries are re-loaded from the file on server restart.

### API credit dashboard

The strip at the top of the Workspace shows, per provider, what this app has
spent — this month and all-time.

**What it can and cannot know.** None of the supported providers exposes a
remaining-balance endpoint to a normal API key — balances live in the billing
console, and the OpenAI/Anthropic cost APIs need an org-admin key and report
*spend*, not what remains. So the dashboard works from the other end:

- every call the app makes is already in `ai_requests.jsonl`, now including the
  token counts the provider itself returned with the response;
- those tokens are priced locally (see below) to give spend per provider,
  month-to-date and all-time;
- every card links to that provider's billing page — the authoritative number.

Calls made on the same key from anywhere else (another tool, a colleague's
machine) are invisible here, by construction.

Providers that are not billed per token say so instead: Ollama is **free**
(local inference) and M365 Copilot is a **per-seat licence**.

**Rates** are USD per 1M tokens, in `pricing.json`. Seeded defaults cover the
model families the app recognises (Claude opus/sonnet/haiku, GPT/o-series,
Gemini pro/flash/flash-lite) and are *published list prices* — they drift, they
ignore batch/cache discounts, and they never match a negotiated or regional
rate. A model we have no rate for (including every Azure deployment, whose name
says nothing about its price) has its tokens counted but contributes $0.00 to
the spend figure — so a card can understate what you actually spent. Give it a
rate with `POST /credits/rate` (`{"model": ..., "input_per_m": 3,
"output_per_m": 15}`) or by editing `pricing.json` directly; costs are computed
at read time, so history re-prices immediately.

Requests logged before token capture existed are marked **estimated** — their
tokens are inferred from character counts (~4 chars/token).

**Cost per conversation.** The Result pane shows a running total for the open
conversation next to the masking badge — `$0.59 · 3 call(s)`, hover for tokens
and model. It covers everything billed under that conversation id: the opening
**Mask & Analyse** plus every follow-up. Ending the conversation closes it out
with a final figure in the closing message:

> 💵 This conversation cost **$0.0057** — 3 call(s), 6.2K tokens on
> gemini-3.5-flash.

Connection tests aren't part of any conversation, so they never land on one.
`/analyze`, `/chat` and `/chat/end` each return the total in a `cost` field if
you want it from the API.

### Pre-send leak guard

Before anything is sent, a **second, independent** scanner checks the already-
masked text — deliberately not reusing the masking engine's patterns, so it
catches exactly the failures the masker can't see:

- a value that was masked elsewhere but is still visible somewhere (partial
  masking) — **blocking**
- a custom always-mask term that slipped through — **blocking**
- IP addresses / email addresses left unmasked (e.g. after a bad edit to a
  built-in regex in the pattern editor) — **blocking**
- secret-shaped high-entropy tokens and hostname-like asset names the
  patterns didn't know about — **advisory**

Advisory findings appear as a strip in the **Sent to AI** tab (live, during
preview). Blocking findings stop **Mask & Analyse** and follow-up questions
cold — nothing leaves the machine — and open a dialog where the analyst can
**➕ mask** the value (adds it to custom terms and re-masks) or explicitly
**send anyway**. Acknowledgements are recorded in the request audit log
(`ai_requests.jsonl`) and badged 🚨 in the Requests tab, so every override is
attributable and reviewable. Checks for a category the analyst deliberately
switched off are skipped.

### System prompt (editable + optional per run)

The instructions sent to the AI before your logs (analyst persona +
placeholder-preservation rules) live in **⚙ Setup → System prompt**, where you
can **edit and Save** your own version or **↺ Reset to default**. A custom
prompt persists in `app_config.json` and survives restarts.

Each analysis carries a **Use system prompt** toggle in the Raw logs panel
(on by default). Untick it to send only your logs plus any *Extra analysis
instructions* — useful when you want the model's unguided take or are supplying
your own framing. The toggle is per-run; it never changes the saved prompt.

### Structured verdict

With **Structured verdict** ticked (default), the AI is asked to end its
analysis with a fixed schema — verdict (`true_positive` / `false_positive` /
`benign_true_positive` / `inconclusive`), confidence, severity, MITRE ATT&CK
techniques, IOCs, affected entities, recommended actions, and next steps. The
app parses that block out of the response, restores the real values into it
locally, and renders it as a colour-coded **verdict card** above the prose.
**⧉ Copy JSON** / **⬇ JSON** export the verdict (with real values) for pasting
into a SOAR incident or case record. Follow-up questions update the card if the
assessment changes. The parsing is on the *masked* response and tolerant of
malformed output — a missing or broken block just falls back to plain prose.

### Persistent entity vault (cross-incident correlation)

By default, placeholders are stable across your **entire history**, not just
one conversation: once `WS-FIN-07` becomes `[HOST_12]`, it is `[HOST_12]` in
every future incident. The vault stores each entity (placeholder, real value,
first/last seen) together with the incidents it appeared in and the structured
verdict the AI reached — encrypted in `entity_vault.enc` with a key held in
your **OS keychain** (git-ignored; real values never leave the machine).

That unlocks cross-incident correlation without exposing data:

- **Cross-incident context in the prompt** — with the *Cross-incident
  context* toggle on (default), recurring entities get a history block
  appended to the system prompt, e.g. `[HOST_12]: seen in 3 prior analyses
  (first 2026-06-14, last 2026-07-01; verdicts: true_positive ×2)`. The AI
  can reason "this host is a repeat offender" while seeing **placeholder
  statistics only** — ids, dates, counts, verdict labels; never real values.
  The block appears verbatim in the full-prompt preview and the audit log.
- **🗄 Entity Vault view** — every remembered entity with its alias, real
  value (local), incident history and per-incident verdicts; filter by alias,
  type, or value. **✕ forget** removes one entity — its number is *retired*,
  never reused, so an old analysis can never silently point at a different
  entity. **🗑 Clear vault** wipes everything and restarts numbering.
- **Vault enabled** toggle (persisted) switches the feature off entirely:
  numbering restarts per conversation and nothing new is remembered.

### Conversations & masking

Follow-up questions are masked with the **same cumulative mapping** as the
log: a value masked earlier (say `jsmith` → `[USER_1]`) is re-masked with the
same placeholder even if you type it verbatim in a question and no generic
pattern would catch it; brand-new values continue the numbering. Each turn
sends the full masked history, so the model remembers earlier turns without
ever seeing a real value. Conversations live only in the local server's
memory — ending one (or restarting the server) forgets it.

## Tests

```bash
python test_masker.py      # masking, leak guard, prompt assembly
python test_vault.py       # persistent entity vault
python test_providers.py   # provider abstraction + usage capture
python test_credits.py     # pricing and spend accounting
python test_security.py    # request guard, data paths, secret storage
python test_cli.py         # launcher: start/stop/status on this OS
python test_regexlab.py    # regex workbench: diagnosis and suggestions
node   test_frontend.js    # log-file encoding detection (browser-side)
```

All of them run from `log_masker_app/` with no test runner and no plugins.
The CI matrix runs them on macOS, Windows and Linux against Python 3.11 and
3.13.
