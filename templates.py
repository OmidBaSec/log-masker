"""
SOC analyst prompt-template library.

Each template pairs a ready-made analysis instruction (appended to the system
prompt when the analyst picks it) with its MITRE ATT&CK tactic + technique, and
a set of `signals` — (weight, compiled regex) pairs used to auto-suggest the
most relevant templates from a pasted raw log.

Nothing here masks or calls out; suggestion runs locally on the raw text. The
matched substrings are NOT returned, only template ids + scores, so no raw log
content leaks through the suggestion path.
"""

import json
import os
import re
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Template definitions. `signals` weights are summed per template; the strings
# are case-insensitive regexes matched against the raw log.
# ---------------------------------------------------------------------------
_RAW_TEMPLATES: List[dict] = [
    {
        "id": "brute_force",
        "name": "Brute force / password spraying",
        "category": "Credential Access",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "prompt": (
            "Investigate possible brute-force or password-spraying activity. "
            "Count authentication failures per source IP and per account, "
            "identify the targeted accounts and any eventual success after "
            "repeated failures (a likely compromise), note the time window and "
            "rate of attempts, and call out lockouts. Recommend containment "
            "(block source, reset credentials) and detection improvements."
        ),
        "signals": [
            (3, r"failed password|authentication fail|auth failure|login failed"),
            (3, r"\b4625\b|\b4771\b"),                 # Win failed logon / kerb
            (2, r"invalid user|unknown user|bad password"),
            (2, r"accepted password.*after|success.*after .*fail"),
            (2, r"account lock|lockout|locked out"),
            (1, r"sshd|ssh2"),
        ],
    },
    {
        "id": "valid_account_login",
        "name": "Suspicious successful logon / valid accounts",
        "category": "Initial Access",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique": "Valid Accounts",
        "technique_id": "T1078",
        "prompt": (
            "Assess whether this successful authentication is legitimate or an "
            "abuse of valid credentials. Consider logon type, source geography "
            "and IP reputation, impossible-travel, off-hours access, new device "
            "or new source, and whether the account normally logs in this way. "
            "Flag anomalies and recommend verification steps."
        ),
        "signals": [
            (3, r"\b4624\b"),                          # Win successful logon
            (2, r"accepted password|accepted publickey|logon success"),
            (2, r"logon type|interactive|remoteinteractive"),
            (2, r"new sign-in|unfamiliar location|impossible travel"),
        ],
    },
    {
        "id": "lateral_movement",
        "name": "Lateral movement (RDP/SMB/WinRM/PsExec)",
        "category": "Lateral Movement",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "technique": "Remote Services",
        "technique_id": "T1021",
        "prompt": (
            "Look for lateral movement between hosts. Trace authentication and "
            "session events across systems (RDP, SMB/admin shares, WinRM, "
            "PsExec/SMB service creation, WMI), build the source→destination "
            "host chain and the accounts used, and distinguish admin activity "
            "from attacker pivoting. Recommend segmentation and monitoring."
        ),
        "signals": [
            (3, r"psexec|paexec|\bwinrm\b|wmiexec|smbexec"),
            (3, r"\b4648\b|\b4624\b.*type\s*[:=]?\s*3|logon type\s*[:=]?\s*10"),
            (2, r"\brdp\b|terminal services|mstsc|3389"),
            (2, r"admin\$|ipc\$|c\$|\\\\[\w.-]+\\[a-z]+\$"),
            (2, r"\b7045\b|service control manager|new service"),
            (1, r"\b445\b|\b5985\b|\b5986\b"),
        ],
    },
    {
        "id": "privilege_escalation",
        "name": "Privilege escalation",
        "category": "Privilege Escalation",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "technique": "Abuse Elevation Control Mechanism",
        "technique_id": "T1548",
        "prompt": (
            "Determine whether an account gained elevated privileges. Look for "
            "additions to privileged groups, UAC bypass, sudo/su to root, "
            "token manipulation, special-privilege assignment at logon, and "
            "newly granted admin rights. Identify who escalated whom, when, and "
            "via what mechanism; recommend least-privilege remediation."
        ),
        "signals": [
            (3, r"\b4672\b|special privileges|sedebugprivilege|setakeowner"),
            (3, r"\b4728\b|\b4732\b|\b4756\b|added to.*(admin|domain admins)"),
            (2, r"\bsudo\b|su\[|to root|uid=0|runas|elevation"),
            (2, r"uac|bypassuac|consent\.exe|fodhelper|token manipulation"),
        ],
    },
    {
        "id": "persistence",
        "name": "Persistence (services, tasks, run keys, accounts)",
        "category": "Persistence",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "technique": "Scheduled Task/Job",
        "technique_id": "T1053",
        "prompt": (
            "Hunt for persistence mechanisms: scheduled tasks/cron jobs, new "
            "or modified services, Run/RunOnce registry keys, startup folder "
            "entries, WMI event subscriptions, and newly created or re-enabled "
            "accounts. For each, note what runs, as which user, and its "
            "trigger; assess legitimacy and recommend removal."
        ),
        "signals": [
            (3, r"schtasks|scheduled task|\b4698\b|cron(tab)?|at\.exe"),
            (3, r"\b7045\b|new service|service creation|systemctl enable"),
            (2, r"run(once)?\\|currentversion\\run|registry.*\\run\b"),
            (2, r"\b4720\b|user account.*created|adduser|useradd|net user .*\/add"),
            (2, r"wmi.*subscription|eventconsumer|startup folder"),
        ],
    },
    {
        "id": "execution_scripting",
        "name": "Suspicious execution (PowerShell / scripting / LOLBins)",
        "category": "Execution",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique": "Command and Scripting Interpreter",
        "technique_id": "T1059",
        "prompt": (
            "Analyse process execution for malicious tradecraft: encoded or "
            "obfuscated PowerShell (-enc, FromBase64String, IEX), living-off-"
            "the-land binaries (mshta, rundll32, regsvr32, certutil, wmic), "
            "suspicious parent/child chains (office→shell), and download-and-"
            "execute. Decode where possible and assess intent."
        ),
        "signals": [
            (3, r"powershell.*(-enc|-e |frombase64|-nop|-w hidden|iex|invoke-expression)"),
            (3, r"mshta|rundll32|regsvr32|certutil|bitsadmin|wmic\b"),
            (2, r"cmd\.exe\s*/c|/k\s|wscript|cscript|\bbash -c\b|curl .*\|\s*sh"),
            (2, r"\b4688\b|process create|sysmon.*event id.*1|new process"),
            (2, r"downloadstring|downloadfile|invoke-webrequest|new-object net\.webclient"),
        ],
    },
    {
        "id": "defense_evasion",
        "name": "Defense evasion / log tampering",
        "category": "Defense Evasion",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique": "Indicator Removal",
        "technique_id": "T1070",
        "prompt": (
            "Check for attempts to evade defenses or destroy evidence: cleared "
            "event logs, disabled AV/EDR or security services, deleted shadow "
            "copies, tampered audit policy, and timestomping. Establish what "
            "was disabled/cleared, by whom, and whether it precedes other "
            "malicious activity."
        ),
        "signals": [
            (3, r"\b1102\b|\b104\b|event log (was )?cleared|wevtutil cl|clear-eventlog"),
            (3, r"vssadmin.*delete|shadowcopy.*delete|wbadmin delete|bcdedit"),
            (2, r"defender.*(disabl|off)|set-mppreference|stop.*(av|edr|sense)"),
            (2, r"auditpol.*(disable|clear)|timestomp|attrib \+h"),
        ],
    },
    {
        "id": "discovery",
        "name": "Discovery / reconnaissance",
        "category": "Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique": "Account Discovery",
        "technique_id": "T1087",
        "prompt": (
            "Identify internal reconnaissance: host, account, group, share, "
            "domain-trust and network enumeration (whoami, net, nltest, "
            "ipconfig, arp, AdFind, BloodHound/SharpHound). Group commands by "
            "host and account, and judge whether the pattern looks automated "
            "or like hands-on-keyboard recon ahead of further attack."
        ),
        "signals": [
            (3, r"bloodhound|sharphound|adfind|nltest|dsquery"),
            (2, r"\bwhoami\b|net (user|group|view|localgroup)|net1 \b"),
            (2, r"\bnmap\b|masscan|arp -a|ipconfig /all|systeminfo|nslookup"),
            (2, r"ldapsearch|get-aduser|get-adcomputer|enum"),
        ],
    },
    {
        "id": "c2_beaconing",
        "name": "Command & control / beaconing",
        "category": "Command and Control",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "technique": "Application Layer Protocol",
        "technique_id": "T1071",
        "prompt": (
            "Look for command-and-control: regular-interval beaconing to a "
            "single destination, long-lived connections, suspicious user-"
            "agents, newly registered or rare domains, large response sizes, "
            "and known C2 framework patterns (Cobalt Strike, Sliver, Metasploit). "
            "Assess periodicity and recommend blocking/IOC extraction."
        ),
        "signals": [
            (3, r"cobalt\s*strike|beacon|sliver|meterpreter|empire|covenant"),
            (2, r"user-agent.*(curl|python|powershell|go-http|wget)"),
            (2, r"beacon(ing)?|jitter|callback|c2\b|command and control"),
            (2, r"\.onion|dyndns|no-ip|duckdns|ngrok|pastebin\.com/raw"),
            (1, r"GET /[a-z0-9]{6,}\s|POST /[a-z0-9]{6,}\s"),
        ],
    },
    {
        "id": "dns_tunneling",
        "name": "DNS tunneling / DNS exfiltration",
        "category": "Command and Control",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "technique": "DNS",
        "technique_id": "T1071.004",
        "prompt": (
            "Examine DNS activity for tunneling/exfiltration: abnormally long "
            "or high-entropy subdomains, high query volume to one domain, "
            "unusual record types (TXT, NULL), and base32/base64-looking "
            "labels. Identify the suspect domain and client, estimate data "
            "volume, and recommend sinkholing."
        ),
        "signals": [
            (3, r"\bdns\b.*\b(txt|null)\b|query: .*\b(txt|null)\b"),
            (2, r"named|bind|dnsmasq|query:|resolver"),
            (2, r"[a-z0-9]{30,}\.[a-z0-9-]+\.[a-z]{2,}"),   # long subdomain label
            (2, r"dns ?tunnel|iodine|dnscat"),
        ],
    },
    {
        "id": "exfiltration",
        "name": "Data exfiltration",
        "category": "Exfiltration",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "technique": "Exfiltration Over Alternative Protocol",
        "technique_id": "T1048",
        "prompt": (
            "Investigate potential data exfiltration: large outbound transfers, "
            "uploads to cloud storage or paste sites, archive creation before "
            "transfer (zip/rar/7z/tar), use of FTP/SFTP/SCP, and unusual "
            "destinations or volumes. Quantify bytes out, identify the data and "
            "channel, and recommend DLP/blocking."
        ),
        "signals": [
            (3, r"bytes_out|bytes sent|out=\d{6,}|sc-bytes \d{6,}|\d{7,}\s*bytes"),
            (2, r"mega\.nz|dropbox|wetransfer|pastebin|anonfiles|transfer\.sh|drive\.google"),
            (2, r"\.(zip|rar|7z|tar\.gz|tgz)\b|rar a |7z a |compress-archive"),
            (2, r"\bftp\b|sftp|scp |put \S+|curl -T|upload"),
        ],
    },
    {
        "id": "ransomware_impact",
        "name": "Ransomware / destructive impact",
        "category": "Impact",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique": "Data Encrypted for Impact",
        "technique_id": "T1486",
        "prompt": (
            "Assess for ransomware or destructive impact: mass file rename/"
            "encryption, ransom notes, shadow-copy deletion, backup tampering, "
            "and disabling of recovery. Establish the blast radius (hosts, "
            "shares), the earliest indicator, and the likely entry/spread path; "
            "recommend isolation and recovery steps."
        ),
        "signals": [
            (3, r"ransom|\.lock(ed|y|bit)|\.crypt|readme.*decrypt|how_to_decrypt|\.onion"),
            (3, r"vssadmin.*delete shadows|wmic shadowcopy delete|wbadmin delete catalog"),
            (2, r"mass (rename|encrypt)|bcdedit.*recoveryenabled no|cipher /w"),
            (2, r"lockbit|conti|blackcat|alphv|ryuk|revil|akira"),
        ],
    },
    {
        "id": "account_manipulation",
        "name": "Account creation / manipulation",
        "category": "Persistence",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "technique": "Account Manipulation",
        "technique_id": "T1098",
        "prompt": (
            "Review identity changes for attacker persistence: new accounts, "
            "password resets, group-membership changes, enabling of disabled "
            "accounts, and added credentials/keys (e.g. cloud access keys, "
            "service principals). Determine who made each change and whether it "
            "was authorised."
        ),
        "signals": [
            (3, r"\b4720\b|\b4722\b|\b4724\b|\b4738\b|user account.*(created|enabled|changed)"),
            (2, r"useradd|adduser|net user .*\/add|new-aduser|passwd "),
            (2, r"access key created|createaccesskey|add.*credential|service principal"),
            (2, r"password reset|set password|reset-password"),
        ],
    },
    {
        "id": "web_attack",
        "name": "Web application attack (injection / exploit)",
        "category": "Initial Access",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
        "prompt": (
            "Analyse web/proxy/WAF logs for exploitation of a public-facing "
            "app: SQL injection, XSS, path traversal, command injection, and "
            "known-CVE probe patterns. Identify the targeted endpoints, the "
            "payloads, response codes (did anything return 200/500?), and the "
            "source; judge success and recommend WAF/patching."
        ),
        "signals": [
            (3, r"union\s+select|or\s+1=1|' or '|sleep\(\d|benchmark\(|information_schema"),
            (3, r"\.\./\.\./|%2e%2e%2f|/etc/passwd|c:\\windows\\win\.ini"),
            (2, r"<script>|onerror=|javascript:|alert\(|%3cscript"),
            (2, r"\b(GET|POST)\b.*\b(40[0-9]|500)\b|waf|mod_security|owasp"),
            (1, r"sqlmap|nikto|acunetix|burp"),
        ],
    },
    {
        "id": "phishing",
        "name": "Phishing / suspicious email",
        "category": "Initial Access",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique": "Phishing",
        "technique_id": "T1566",
        "prompt": (
            "Review mail-gateway/transport logs for phishing: spoofed or "
            "look-alike senders, SPF/DKIM/DMARC failures, suspicious "
            "attachments or URLs, and recipients who clicked or replied. "
            "Identify the campaign, affected users, and indicators; recommend "
            "claw-back and user notification."
        ),
        "signals": [
            (3, r"spf=fail|dkim=fail|dmarc=fail|dmarc.*(quarantine|reject)"),
            (2, r"phish|spam|quarantine|spamscore|spam score|reputation"),
            (2, r"postfix|sendmail|exim|message-id|from=<|rcpt to"),
            (2, r"attachment|\.(html|htm|docm|xlsm|iso|img|lnk) (attach|file)"),
        ],
    },
]


def _compile(raw: List[dict]) -> List[dict]:
    out = []
    for t in raw:
        t = dict(t)
        t["signals"] = [(w, re.compile(rx, re.IGNORECASE)) for w, rx in t["signals"]]
        t["max_score"] = sum(w for w, _ in t["signals"]) or 1
        out.append(t)
    return out


_BUILTIN = _compile(_RAW_TEMPLATES)
_BUILTIN_BY_ID = {t["id"]: t for t in _BUILTIN}

# Fields the analyst can edit (signals/keywords handled separately).
EDITABLE_FIELDS = ("name", "category", "tactic", "tactic_id",
                   "technique", "technique_id", "prompt")


# ---------------------------------------------------------------------------
# Persistence. templates_store.json holds:
#   {"overrides": {id: {field: value, ...}},   # edits to built-in templates
#    "custom":    [ {id, ...fields, keywords:[...]} ]}  # analyst-created ones
# Custom templates auto-suggest via simple keyword signals (each keyword is a
# case-insensitive substring match, weight 2).
# ---------------------------------------------------------------------------
STORE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "templates_store.json")


def _load_store() -> dict:
    try:
        with open(STORE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"overrides": {}, "custom": []}
    if not isinstance(data, dict):
        return {"overrides": {}, "custom": []}
    overrides = data.get("overrides")
    custom = data.get("custom")
    return {"overrides": overrides if isinstance(overrides, dict) else {},
            "custom": custom if isinstance(custom, list) else []}


def _save_store(store: dict) -> None:
    with open(STORE_FILE, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, ensure_ascii=False)


def _signals_from_keywords(keywords: List[str]):
    out = []
    for kw in keywords or []:
        kw = (kw or "").strip()
        if kw:
            out.append((2, re.compile(re.escape(kw), re.IGNORECASE)))
    return out


def _compile_custom(raw: dict) -> dict:
    t = dict(raw)
    t["custom"] = True
    t.setdefault("keywords", [])
    t["signals"] = _signals_from_keywords(t.get("keywords"))
    t["max_score"] = sum(w for w, _ in t["signals"]) or 1
    return t


def _build() -> List[dict]:
    """Effective template list: built-ins with overrides applied, then the
    analyst's custom templates."""
    store = _load_store()
    overrides = store["overrides"]
    out = []
    for t in _BUILTIN:
        ov = overrides.get(t["id"])
        if ov:
            merged = dict(t)
            for k, v in ov.items():
                if k in EDITABLE_FIELDS:
                    merged[k] = v
            out.append(merged)
        else:
            out.append(t)
    for c in store["custom"]:
        if isinstance(c, dict) and c.get("id") and c.get("name"):
            try:
                out.append(_compile_custom(c))
            except re.error:
                continue
    return out


_TEMPLATES = _build()


def reload() -> None:
    global _TEMPLATES
    _TEMPLATES = _build()


def _public(t: dict) -> dict:
    """Template fields safe to expose to the UI (no compiled regexes)."""
    is_custom = bool(t.get("custom"))
    modified = (not is_custom) and (t["id"] in _load_store()["overrides"])
    out = {
        "id": t["id"], "name": t["name"], "category": t["category"],
        "tactic": t["tactic"], "tactic_id": t["tactic_id"],
        "technique": t["technique"], "technique_id": t["technique_id"],
        "prompt": t["prompt"],
        "mitre": f"{t['tactic']} ({t['tactic_id']}) · "
                 f"{t['technique']} {t['technique_id']}",
        "custom": is_custom,
        "modified": modified,
    }
    if is_custom:
        out["keywords"] = list(t.get("keywords", []))
    return out


def list_templates() -> List[dict]:
    return [_public(t) for t in _TEMPLATES]


def get_template(template_id: str) -> Dict:
    for t in _TEMPLATES:
        if t["id"] == template_id:
            return _public(t)
    return {}


# ---------------------------------------------------------------------------
# Editing API. Raises ValueError on bad input; callers map that to HTTP 400.
# ---------------------------------------------------------------------------
def _slugify(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "_", (name or "").lower()).strip("_")
    return base or "template"


def _clean_fields(fields: dict) -> dict:
    out = {}
    for k in EDITABLE_FIELDS:
        if k in fields and fields[k] is not None:
            out[k] = str(fields[k]).strip()
    if "name" in out and not out["name"]:
        raise ValueError("Name must not be empty.")
    if "prompt" in out and not out["prompt"]:
        raise ValueError("Prompt must not be empty.")
    return out


def save_template(template_id: str, fields: dict) -> dict:
    """Edit an existing template (built-in override or custom in place)."""
    store = _load_store()
    clean = _clean_fields(fields)
    if template_id in _BUILTIN_BY_ID:
        default = _BUILTIN_BY_ID[template_id]
        ov = dict(store["overrides"].get(template_id, {}))
        for k, v in clean.items():
            if v == default[k]:
                ov.pop(k, None)          # equal to default -> not an override
            else:
                ov[k] = v
        if ov:
            store["overrides"][template_id] = ov
        else:
            store["overrides"].pop(template_id, None)
        _save_store(store)
        reload()
        return get_template(template_id)
    # custom template
    for c in store["custom"]:
        if c.get("id") == template_id:
            c.update(clean)
            if "keywords" in fields and isinstance(fields["keywords"], list):
                c["keywords"] = [str(k).strip() for k in fields["keywords"]
                                 if str(k).strip()]
            _save_store(store)
            reload()
            return get_template(template_id)
    raise ValueError(f"No such template: {template_id}")


def create_template(fields: dict) -> dict:
    """Create a new custom template. `fields` needs at least name + prompt;
    optional `keywords` (list) drive auto-suggestion."""
    clean = _clean_fields(fields)
    if "name" not in clean or "prompt" not in clean:
        raise ValueError("A new template needs a name and a prompt.")
    store = _load_store()
    used = set(_BUILTIN_BY_ID) | {c.get("id") for c in store["custom"]}
    base = _slugify(clean["name"])
    tid, i = base, 2
    while tid in used:
        tid, i = f"{base}_{i}", i + 1
    entry = {
        "id": tid,
        "name": clean["name"],
        "category": clean.get("category", "Custom"),
        "tactic": clean.get("tactic", "Custom"),
        "tactic_id": clean.get("tactic_id", ""),
        "technique": clean.get("technique", ""),
        "technique_id": clean.get("technique_id", ""),
        "prompt": clean["prompt"],
        "keywords": [str(k).strip() for k in (fields.get("keywords") or [])
                     if str(k).strip()],
    }
    store["custom"].append(entry)
    _save_store(store)
    reload()
    return get_template(tid)


def delete_template(template_id: str) -> None:
    """Delete a custom template. Built-ins can't be deleted (use reset)."""
    store = _load_store()
    before = len(store["custom"])
    store["custom"] = [c for c in store["custom"] if c.get("id") != template_id]
    if len(store["custom"]) == before:
        if template_id in _BUILTIN_BY_ID:
            raise ValueError("Built-in templates can't be deleted — use Reset.")
        raise ValueError(f"No such template: {template_id}")
    _save_store(store)
    reload()


def reset_template(template_id: str) -> dict:
    """Drop edits to a built-in template, restoring its default."""
    if template_id not in _BUILTIN_BY_ID:
        raise ValueError("Only built-in templates can be reset.")
    store = _load_store()
    store["overrides"].pop(template_id, None)
    _save_store(store)
    reload()
    return get_template(template_id)


def suggest(raw_log: str, limit: int = 3, min_score: float = 0.12) -> List[dict]:
    """Rank templates by how strongly the raw log matches their signals.

    Returns up to `limit` templates scoring above `min_score`, each with a
    normalised 0..1 `score` and the count of distinct signals that fired.
    Only template metadata + scores are returned — never matched log text.
    """
    if not raw_log or not raw_log.strip():
        return []
    scored: List[Tuple[float, int, dict]] = []
    for t in _TEMPLATES:
        hit = 0.0
        fired = 0
        for weight, rx in t["signals"]:
            if rx.search(raw_log):
                hit += weight
                fired += 1
        if hit <= 0:
            continue
        score = hit / t["max_score"]
        scored.append((score, fired, t))
    # Strongest first; break ties by number of distinct signals that fired.
    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
    out = []
    for score, fired, t in scored:
        if score < min_score:
            continue
        item = _public(t)
        item["score"] = round(score, 3)
        item["signals_fired"] = fired
        out.append(item)
        if len(out) >= limit:
            break
    return out
