# Changelog

All notable changes to Log Masker. Format follows [Keep a Changelog][kac];
versions follow [Semantic Versioning][semver].

[kac]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Added
- **Sysmon (Windows & Linux) pattern group**, editable as a unit in the
  built-in regex library. Sysmon emits the same field names in three shapes —
  the Event Viewer `Field: value` render, forwarded XML (`<Data Name='…'>`)
  and shipper JSON — and the group reads `User` / `ParentUser` / `SourceUser`
  / `TargetUser`, `SourceHostname` / `DestinationHostname` (event 3) and
  `QueryName` (event 22) in all three. Each field is taken as a whole value at
  Sysmon priority, which catches what the generic `key=value` rules cannot: a
  non-ASCII personal name (their value class is ASCII-only) and a single-label
  DNS query, which has no dot for the FQDN pattern to find.
- The built-in regex library lists its log-source groups alphabetically.
- **Regex workbench**, in the Workspace under the masked output: select a
  value that got through and get the regex change that fixes it, entirely
  on this machine. It sits where the problem is noticed — the value and
  the line it came from fill themselves in, and saving a rule re-masks the
  log immediately so you can see whether the value is actually gone. A log too sensitive to hand an AI provider is also
  too sensitive to paste into an online regex tester, so the tool that repairs
  the masking now lives behind the same wall as the data.
  - Separates the four reasons a value survives, because they have four
    different fixes: nothing matched, a pattern matched and an accept rule
    dropped the value (it names the rule), a protected span claimed it, or a
    higher-priority pattern got there first.
  - Prefers widening the built-in that should have caught the value over
    adding a new pattern, and picks the right one: an indented
    `Requesting Workstation:` line goes to the Windows Event Log pattern, not
    to the generic `host=` one.
  - Every proposal is verified at the pattern's real priority before it is
    offered, and each shows what else it would newly mask in the sample.
  - A value the masker excludes on purpose (`NT AUTHORITY\SYSTEM`,
    `BUILTIN\Administrators`, `localhost`) cannot be rescued by a better
    regex: the accept rule vetoes whatever is captured, so a saved pattern
    looks right and masks nothing, every run. The workbench now proposes those
    under the `CUSTOM` label, which the accept rules do not police, and
    repeats why the value was excluded so the trade is explicit.
  - `mask()` takes `builtin_patches` so a candidate can be previewed at its
    true priority without saving an override or swapping global state that a
    concurrent request could see.

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

- **The sidebar can be hidden** with the header's ☰ button or ⌘B/Ctrl+B,
  giving the workspace the full width. The toggle stays in the header so
  there is a way back, and the state is restored before first paint.

- The analyze button is called **Analyze by AI**. It used to say "Mask &
  Analyse", which read as though masking waited for the click — it does not,
  it runs as you type. The button does the one thing that actually leaves the
  machine. The README said to press a "Preview masking" button that has not
  existed for some time; it now describes what happens.
- Every user-facing "analyse/analysing/analysed" is now spelled the American
  way, matching the `analyze` already used throughout the code and the
  `/analyze` endpoint. "Analysis" and the plural "analyses" are unchanged —
  they are spelled the same either way.

- **Never-mask terms** — the answer to "it masked something that is not
  confidential". Click the red placeholder in *Masked data*: it shows the real
  value, and one confirmation rules it non-sensitive for good. The value is
  also forgotten from the entity vault, which is the part that makes the rule
  actually work — the vault re-masks everything it has ever seen regardless of
  the patterns, so without that the value would keep coming back and the rule
  would look broken. The leak guard learns about it too, so a ruling does not
  leave a blocking finding behind it. Managed under Masking Rules → Never-Mask
  Terms. Use it when one value is wrong; use the regex workbench when a whole
  class of value is.

### Fixed
- A user name could be masked **in part**, sending the rest in clear:
  `ParentUser: ACME\a.karimi` came out as `[USER_3]karimi` whenever a later
  line began with `=`, because the "this is a key, not a value" guard scanned
  past the end of the line. It now stops at the line it is on.
- A space inside a Windows path let `DOMAIN\user` start half way through one,
  so `C:\Program Files\Acme Suite\agent.exe` was shredded into
  `C:\Program [USER_1] [USER_2]`. A directory word on the left of the
  backslash, or a file name on the right, now says "this is a path".
- The `net use … /user:DOM\svc <password>` rule ran past the end of the
  password in forwarded XML, masking `Sup3rSecret!</Data><Data` as one secret
  and breaking the document it was in.
- Values that describe the log format rather than the customer are no longer
  masked: the `xmlns` schema URL, the provider GUID of the Sysmon channel,
  WMI namespaces and consumer classes (`root\cimv2`,
  `CommandLineEventConsumer.Name`) from events 19-21, and well-known short
  SIDs under a key (`UserID='S-1-5-18'`), which the SID pattern already left
  readable on purpose.
- Linux daemon accounts (`postfix`, `www-data`, `syslog`, `nobody`, …) are
  treated like the built-in Windows accounts they are the equivalent of. They
  identify nobody, and masking `postfix` also shredded the binary path it
  appeared in (`/usr/lib/[USER_5]/sbin/smtp`).
- **`/etc/cron.hourly` was masked as a hostname.** It is dotted like a domain
  and `.hourly` is on no file-extension list, so every cron line came back
  with a stock Linux path redacted out of it. Same for systemd unit names
  (`session-42.scope`, `nginx.service`). A dotted name inside a filesystem
  path is now read as a path component — except where the suffix really is a
  domain suffix, so `/var/www/acme.com/htdocs` is still masked, and masked
  whole rather than from its second label on.
- **Hovering a masked placeholder showed nothing.** The hover card was drawn
  above the token, which put it outside the `<pre>` that scrolls — so for
  anything on the first line, the card was clipped away before it could be
  seen. Moving it to `position: fixed` was not enough either: the panel has a
  `backdrop-filter`, which makes it the containing block for fixed descendants
  and clips them too. The card is now a single element at `<body>` level,
  positioned on hover and flipped below the token when there is no room above.
  A large log also stops carrying one hidden card per placeholder.
- The hover card inherited an `all` transition, so the `left`/`top` set on it
  animated: it slid across the screen from wherever it was last shown. It now
  transitions opacity and transform only.
- **A forwarded Windows event could have half its Message masked as one
  token.** `Group Name:  Administrators  Group Domain:  Builtin  …` has no
  comma to stop at, so the group pattern ran to the end of the line and
  swallowed every field after it, process path included. Values now also end
  at the two-space or tab separator these single-line Message blobs use, and
  are hard-bounded so no log shape can turn this into a line-eater again.
- An empty field (`User=\tDomain=`) let the capture skip the tab and mask the
  *next key's own name* — the literal word "Domain" came out as a person.
- `PluginVersion=WC.MSEVEN6.10.0.2.62` was masked as the IP address
  `10.0.2.62`. Four octets starting part-way through a longer dotted string
  are a version, not an address.
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
- **`Windows XML & Sysmon` is now `Windows Event Log (XML)`**, and holds only
  the Security-channel fields it is named for. Sysmon's own XML fields moved
  to the Sysmon group: `User` and `ParentUser` were in both groups, and
  `SourceHostname` / `DestinationHostname` were only in the Windows one, so
  "which rule masked this?" had two answers and "where do I edit it?" had the
  wrong one. Nothing changed about what gets masked -- the split is verified
  field by field -- and pattern ids are untouched, so a saved override still
  applies to the same regex.
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
