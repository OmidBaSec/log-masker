# Changelog

All notable changes to Log Masker. Format follows [Keep a Changelog][kac];
versions follow [Semantic Versioning][semver].

[kac]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Added
- **Masking for cloud and SaaS log sources**: AWS CloudTrail, AWS Config,
  AWS S3, AWS Security Hub, Okta, OneLogin, Duo Security, JumpCloud, Entra ID,
  GitHub, Atlassian Jira, Zoom, DocuSign, Dynamics 365, Power Platform, GCP,
  Azure Storage, Office 365, Purview, Defender for Cloud Apps, M365 Defender,
  CylancePROTECT, Imperva WAF Gateway, Qualys VM, Infoblox NIOS, UniFi,
  pfSense, Symantec ProxySG, Cribl and Proofpoint TAP — 23 patterns, in the
  format each product actually sends.
  - New placeholder types: `[ARN]`, `[ASSET]`, `[ORG]`, `[GROUP]`,
    `[SUBJECT]`, `[KEYID]`, `[ACCTID]`.
  - SaaS audit JSON puts the identity under a vendor key with a multi-word
    value; the new patterns anchor on the quoted key and take the whole value,
    so `"displayName":"John Smith"` is one placeholder instead of a masked
    first name and a visible surname.
  - Kept on purpose, because they are the question and not the customer:
    phishing subject lines and attachment names, vendor product ARNs, vendor
    app names (`"appName":"Box"`), and event taxonomies
    (`"action":"repo.destroy"`, `"eventType":"user.session.start"`).

### Fixed
- **JSON Lines is no longer mistaken for a CSV export.** A JSONL log — the
  wire format of most cloud connectors — has commas and quoted tokens like a
  CSV row, so the first record was read as a header: the object's *keys* were
  masked as though they were values, and the real values were left visible.
  A CSV header row never starts with `{` or `[`.
- Dotted lowercase enum values under an event key are no longer masked as
  hostnames, so `"action":"repo.destroy"` survives.
- **PowerShell coverage.** A Windows investigation is conducted in PowerShell,
  so a transcript, a script-block log (event 4104) or a pasted console session
  is one of the most common things to hand this tool — and PowerShell puts its
  identifiers in three shapes no `key=value` pattern could reach:
  - **Parameter arguments**, separated by a space rather than `=` and often a
    list: `-ComputerName WKS-01,WKS-02`, `-Credential`, `-Identity`,
    `-UserName`, `-SamAccountName`, `-Mailbox`, `-ResourceGroupName`. One
    placeholder per list item. `-Name`/`-DisplayName` are resolved from the
    cmdlet on the line, so `New-ADUser -Name "Petra Vogel"` is a person,
    `Get-AzVM -Name vm-web01` is a machine, and `Get-Service -DisplayName
    "Print Spooler"` is neither.
  - **`Format-Table` output**: the row of dashes gives the column boundaries
    and the header says what the cells hold. `Get-LocalUser` and `Get-ADUser`
    tables are masked cell by cell; `Get-Service` and `Get-Process` are not.
  - **`-EncodedCommand`** base64 blobs, decoded locally and masked only when
    the decoding holds something that would have been masked in the clear —
    the same answer either way, which is what makes keeping the rest safe.
  - Plaintext credentials as PowerShell writes them: `ConvertTo-SecureString
    'literal'`, `-Password`, `-AccessToken`, `Bearer` tokens, and the
    positional password of `net use … /user:DOM\svc <password>`.
  - Transcript headers and filenames, `Format-List` person fields
    (`DisplayName`, `GivenName`, `Surname`, `PrimaryOwnerName`), AD attributes
    (`-GivenName`, `-Surname`, `-StreetAddress`), `Get-Credential "DOM\user"`,
    SQL connection strings (`User ID=`), `az login -p`, Azure resource names
    (`-VaultName`, `-ResourceGroupName`) and Graph filter strings.
  - Asset names in prose, where a keyword anchors them and the value carries
    the shape of one: `logged into host WORKSTATION-88`.

### Fixed
- **A masked value could still be sent in the clear elsewhere in the same
  paste.** A pattern anchors on one shape of a name — `Machine: WKS-01` in a
  transcript header — while two lines down `hostname` echoes a bare `WKS-01`
  that nothing marks. The masker now takes a second pass over every value it
  has already decided is sensitive, including the short form of an FQDN and
  the domain half of `DOMAIN\user`. This is the difference between "the
  patterns matched" and "the value is gone".
- `$password = ConvertTo-SecureString 'Wint3r!2026'` masked the *cmdlet name*
  and left the credential standing next to it.
- `\\FS-ARCHIVE-01\payroll$` was shredded into a bogus user
  `ARCHIVE-01\payroll`; `$env:LOGONSERVER` (`\\DC01`, no trailing separator)
  and provider-qualified paths (`FileSystem::\\NAS-01\share`) were missed
  entirely.
- A 13–16 digit run is only a credit card if it passes the Luhn check digit —
  a PowerShell transcript's `Start time: 20260902141233` is a timestamp.
- One value no longer gets two placeholders because two patterns disagreed
  about its label, and the label chosen is the more specific one.
- The pre-send leak guard blocked on `127.0.0.1`, which the masker keeps by
  design — a hard stop in front of every `Get-NetTCPConnection` paste.
- `[System.Net.Dns]`, `$wc.Proxy`, `Microsoft.PowerShell.Core\FileSystem::`
  and built-in groups like `CORP\Domain Users` are no longer masked.
- `-Password (ConvertTo-SecureString "…")` masked the cmdlet *and* swallowed
  the opening parenthesis, leaving the password beside it — and the new
  propagation pass then copied that mistake to every other use of the cmdlet.
- A `-match` pattern is not a log line: `"Account Name:\s+(?<user>\w+)"` was
  masked down to its regex escape, corrupting the command.
- `Server=tcp:…` read `tcp` as a hostname; `User ID=` in a SQL connection
  string was not read as a username at all.
- The bare word form of a NetBIOS domain is no longer chased through prose
  when it is an ordinary word (`STORAGE`, `FINANCE`); the qualified
  `STORAGE\root_backup` is still masked in full.
- The leak guard no longer warns about WMI/CIM class names (`Win32_…`), which
  are long and high-entropy and appear in every PowerShell paste.

### Changed
- **Far fewer false positives on EDR alert JSON.** A Microsoft Defender
  incident went from 25 masked values to 14, with every remaining one genuinely
  customer-identifying. Masking a vendor's schema namespaces, console URLs and
  file hashes protected nobody and made the alert unreadable.
  - File hashes under an explicit hash key are kept — a hash is the IOC. A bare
    `hash=` still masks, because that is where credential dumps put NTLM hashes.
  - Vendor reference ids (`detectorId`, `alertId`, `ruleId`, `correlationId`)
    and ATT&CK ids are kept.
  - Loopback and unspecified addresses are kept.
  - Security-console hostnames are kept, matched exactly — never by suffix, so
    `contoso.sharepoint.com` still masks.
  - camelCase final labels are no longer treated as TLDs, so
    `#microsoft.graph.security.deviceEvidence` is not a hostname.
  - JSON-escaped Windows paths are no longer read as UNC server names, so
    `C:\\Windows\\System32\\WindowsPowerShell` survives intact.

### Security
- The M365 OAuth callback page escapes text that came from the identity
  provider. It renders on the app's own origin, so injected markup would have
  run as same-origin script with the request guard treating it as us.
- Custom Ollama and Azure endpoints are validated before the server fetches
  them: `http`/`https` only, and link-local, carrier-grade-NAT and cloud
  metadata addresses are refused. Loopback stays allowed — that is where Ollama
  runs. Matters once the app is exposed with `LOGMASKER_ALLOW_REMOTE`.
- User-supplied regexes are rejected if they backtrack catastrophically.
  A saved pattern runs on *every* future mask, so one bad pattern wedged every
  analysis — and the leak guard with it — until the JSON was hand-edited. The
  check runs out-of-process, because `re` holds the GIL while it backtracks and
  a thread could not have been timed out.
- The M365 token cache is created owner-only rather than chmod-ed afterwards,
  closing the window where a refresh token sat at 0644.

## [0.9.0] — 2026-08-25

First release prepared for public use. Everything before this was developed in
private, so this entry describes the state rather than the diff.

### Added
- **Runs on macOS, Windows and Linux.** Per-OS data directory (`paths.py`),
  a secret store that falls back to an encrypted file where there is no OS
  keychain (`keystore.py`), and a pure-Python launcher (`log_masker/cli.py`)
  with `run.sh`, `run.ps1` and `run.bat` wrappers.
- **Installable**: `pip install .` provides a `log-masker` console script; the
  UI ships as package data.
- **Container image**: `Dockerfile` (multi-stage, non-root, read-only rootfs)
  and `docker-compose.yml` with an optional Ollama profile.
- **Request guard** (`guard.py`) against CSRF and DNS rebinding, plus a refusal
  to bind a non-loopback interface without an explicit opt-in.
- **Log file encoding detection** — UTF-16 Windows exports were previously
  rejected as binary files.
- **Credit and spend view**: per-provider month-to-date and all-time cost
  priced from the audit log, and a running cost per conversation.
- **Light / dark / follow-the-OS theme.**
- `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `sample_logs/`, and a CI matrix across three operating
  systems and two Python versions.

### Changed
- **Requires Python 3.11+.** On 3.9 the patched Starlette and python-multipart
  cannot be installed at all; `pip-audit` reported 15 known vulnerabilities
  there and reports none now.
- Audit and vault timestamps are ISO-8601 with a UTC offset.
- Masking categories are no longer selectable in the UI; every analysis masks
  identities, network and secrets.

### Fixed
- **Masking was quadratic twice over** — an O(n²) overlap scan and a whole-text
  copy per replacement. A 0.5 MB log took minutes and now takes ~0.3 s, making
  the documented 10 MB limit usable. Output is byte-identical to before.
- Chunked request bodies bypassed the request size limit.
- An origin check accepted any loopback address, so another local app could
  drive this one.
- `UVICORN_HOST` bypassed the non-loopback bind refusal entirely.
- Spreadsheet import had no zip-bomb, cell-count or parse-time limits.
- `./run.sh` with no arguments crashed under `set -u` on macOS's bash 3.2.
- A misconfigured data directory or master key failed with a misleading error.

### Security
- The threat model, and what the tool does *not* guarantee, are documented in
  the README and `SECURITY.md`. Masking is best-effort and pattern-based; the
  audit log evidences what was sent rather than proving nothing leaked.

[Unreleased]: https://github.com/OmidBaSec/log-masker/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/OmidBaSec/log-masker/releases/tag/v0.9.0
