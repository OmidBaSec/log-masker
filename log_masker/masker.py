"""
Local masking / un-masking engine.

Detects sensitive tokens in raw log text and replaces each unique real value
with a stable placeholder (e.g. [EMAIL_1]). The same real value always maps to
the same placeholder, so the AI sees consistent identifiers. Un-masking is a
literal reverse substitution, so it is robust regardless of how the AI reformats
the surrounding text -- as long as the bracketed placeholders survive verbatim.

Nothing here makes a network call. Only the masked text should ever leave the
machine; the mapping stays local.
"""

import json
import os
import re
from typing import Dict, List, Tuple

from log_masker import paths

# ---------------------------------------------------------------------------
# Detection patterns, ordered from most specific to least specific.
#
# Order matters: an email must be caught before its embedded domain, an API key
# before a generic hex blob, etc. Each entry is (category, label, compiled regex).
# `label` is the prefix used in the placeholder, e.g. EMAIL -> [EMAIL_1].
# ---------------------------------------------------------------------------

# Categories map to the UI checkboxes.
CATEGORIES = {
    "identities": "Usernames, emails, person names",
    "network": "Domains, hostnames, IPs, MAC addresses",
    "secrets": "API keys, tokens, UUIDs, credit cards, account numbers",
}

# A small allow-list of common domains/words we never want to mask, because
# masking them adds noise without protecting anything sensitive.
_DOMAIN_ALLOWLIST = {
    "example.com", "localhost", "anthropic.com", "api.anthropic.com",
    "google.com", "microsoft.com", "github.com",
    # Security-console and API hostnames that appear in nearly every alert
    # payload. Exact matches only, never suffixes: "contoso.sharepoint.com"
    # names the tenant and must still be masked.
    "security.microsoft.com", "portal.azure.com", "graph.microsoft.com",
    "login.microsoftonline.com", "login.microsoft.com",
    "protection.office.com", "compliance.microsoft.com",
    "console.aws.amazon.com", "console.cloud.google.com",
    "attack.mitre.org", "virustotal.com", "www.virustotal.com",
}

# Common file extensions / TLD-lookalikes we do NOT want treated as domains.
_NOT_TLDS = {
    "py", "js", "ts", "json", "log", "txt", "md", "html", "css", "exe",
    "dll", "so", "sh", "yml", "yaml", "csv", "xml", "png", "jpg", "gif",
    "conf", "cfg", "ini", "bak", "tmp", "gz", "zip", "tar", "jar", "war",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "msi",
    "bat", "ps1", "vbs", "lnk", "sys", "dat", "db", "mdb", "evtx", "pcap",
    # JSON/telemetry key suffixes ("@odata.type", "event.kind"). Deliberately
    # excludes .id and .name, which are real TLDs — over-masking is noise,
    # under-masking is a leak.
    "type", "kind", "value", "count", "severity", "timestamp", "verdict",
}

# Tokens that sit where a syslog hostname would but are really log levels,
# plus path components that look like UNC server names in JSON-escaped paths.
_NOT_HOSTS = {
    "info", "warn", "warning", "error", "err", "debug", "notice", "trace",
    "fatal", "crit", "critical", "alert", "emerg", "panic", "audit", "verbose",
    "users", "windows", "system32", "programdata", "program files", "temp",
}

# Built-in Windows accounts / placeholder values that appear in event-log
# fields but identify nothing customer-specific.
_WINDOWS_BUILTIN_VALUES = {
    "-", "n/a", "null", "system", "local service", "network service",
    "anonymous logon", "nt authority", "nt", "workgroup", "window manager",
    "font driver host", "dwm-1", "dwm-2", "umfd-0", "umfd-1",
    "administrator", "guest", "public", "default", "default user",
    "defaultuser0", "all users", "local system", "trustedinstaller",
    "root", "https", "http", "ftp", "unknown", "none", "true", "false",
}

# DOMAIN\user matches whose "domain" part is really a built-in prefix
# (NT AUTHORITY\SYSTEM, NT SERVICE\TrustedInstaller, BUILTIN\Administrators).
_BUILTIN_DOMAIN_PREFIXES = {"authority", "service", "builtin"}


def _compile_patterns():
    p: List[Tuple[str, str, "re.Pattern"]] = []

    # --- secrets / ids -----------------------------------------------------
    # Windows SIDs. Must run BEFORE the credit-card pattern, which would
    # otherwise partially swallow the digit groups. Requires the
    # S-1-5-21-... domain part (4+ sub-authorities) so well-known short SIDs
    # like S-1-5-18 (SYSTEM) stay readable.
    p.append(("identities", "SID", re.compile(
        r"\bS-1-\d+(?:-\d+){3,}\b")))
    # Azure resource IDs carry subscription GUIDs plus customer resource-group
    # and resource names. Must run before the UUID pattern so the whole value
    # is masked as one token instead of just the embedded GUID.
    p.append(("network", "RESOURCE", re.compile(
        r"(?i)\"resource[_-]?id\"\s*:\s*\"([^\"]+)\"")))
    # Credit-card-like 13-16 digit groups (optionally separated by - or space).
    p.append(("secrets", "CC", re.compile(
        r"\b(?:\d[ -]?){13,16}\b")))
    # Known API-key shapes (Anthropic, OpenAI, AWS, GitHub, Slack, generic sk-).
    p.append(("secrets", "APIKEY", re.compile(
        r"\b(?:sk-[A-Za-z0-9_\-]{16,}"
        r"|AKIA[0-9A-Z]{16}"
        r"|gh[pousr]_[A-Za-z0-9]{20,}"
        r"|xox[baprs]-[A-Za-z0-9-]{10,}"
        r"|AIza[0-9A-Za-z\-_]{30,})\b")))
    # Bearer / token / password / SNMP-community key=value pairs -> mask the
    # value only. The optional quote before the separator covers JSON keys:
    #   "password": "hunter2"
    p.append(("secrets", "SECRET", re.compile(
        r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|auth|community)"
        r"[\"']?\s*[=:]\s*[\"']?([^\s\"',;]+)")))
    # Device serial numbers (SonicWALL sn=, generic serial=).
    p.append(("secrets", "SERIAL", re.compile(
        r"(?i)\b(?:serial(?:[ _-]?(?:no|num|number))?|sn)=[\"']?"
        r"([A-Za-z0-9\-]{6,})")))
    # WatchGuard Fireware: the device serial that follows the syslog hostname,
    #   Jun 10 14:23:01 FW-HQ-01 80BE052F336C0 (2026-06-10T14:23:01) firewall: …
    p.append(("secrets", "SERIAL", re.compile(
        r"(?m)^(?:<\d+>)?[A-Z][a-z]{2}[ \t]+\d{1,2}[ \t]\d{2}:\d{2}:\d{2}[ \t]+"
        r"\S+[ \t]+([0-9A-F]{12,16})[ \t]+\(")))
    # UUIDs.
    p.append(("secrets", "UUID", re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")))
    # Long opaque hex/base64-ish blobs (>= 32 chars) that look like secrets.
    p.append(("secrets", "HASH", re.compile(
        r"\b[A-Fa-f0-9]{32,}\b")))

    # --- identities --------------------------------------------------------
    # Emails (before domains).
    p.append(("identities", "EMAIL", re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")))
    # Active Directory distinguished names, e.g.
    #   CN=John Smith,OU=Sales,DC=acme,DC=com
    # Masked as one token; requires 2+ components so a lone "DC=..." in prose
    # is not enough to trigger. Values are lazy so the final component stops
    # at the first whitespace instead of swallowing the rest of the line.
    p.append(("identities", "DN", re.compile(
        r"(?im)\b(?:CN|OU|DC)=[^,;\r\n]+?(?:\s*,\s*(?:CN|OU|DC)=[^,;\r\n]+?)+"
        r"(?=[\s,;\"')\]]|$)")))
    # Windows XML event exports (Security XML view, Sysmon via WEF/Winlogbeat):
    #   <Data Name='TargetUserName'>jsmith</Data>
    p.append(("identities", "USER", re.compile(
        r"(?i)<Data Name=[\"'](?:TargetUserName|SubjectUserName|User"
        r"|AccountName|SamAccountName|LogonAccount|ParentUser)[\"']>"
        r"([^<]+)</Data>")))
    p.append(("identities", "DOMAIN", re.compile(
        r"(?i)<Data Name=[\"'](?:TargetDomainName|SubjectDomainName"
        r"|DomainName)[\"']>([^<]+)</Data>")))
    # Windows Event Log indented "Field Name:   value" lines (4624/4625/4720…),
    # e.g. "  Account Name:  jsmith". These field names contain a space, so the
    # generic key=value pattern below cannot catch them.
    p.append(("identities", "USER", re.compile(
        r"(?im)^[ \t]*(?:(?:New |Target |Subject |Caller )?(?:Account|User|Logon) Name"
        r"|Logon Account|Target Account)"
        r"[ \t]*:[ \t]*([^\r\n]+?)[ \t]*$")))
    p.append(("identities", "DOMAIN", re.compile(
        r"(?im)^[ \t]*(?:(?:Target |Subject |Caller )?(?:Account|Logon) Domain"
        r"|Domain Name|Supplied Realm Name)"
        r"[ \t]*:[ \t]*([^\r\n]+?)[ \t]*$")))
    # Usernames embedded in profile paths (Sysmon CommandLine/CurrentDirectory/
    # TargetFilename, IIS, etc.): C:\Users\j.doe\… and /home/j.doe/…
    # Masks only the profile folder name so the path stays readable.
    # `\\+` tolerates JSON-escaped paths ("C:\\Users\\j.smith\\file").
    p.append(("identities", "USER", re.compile(
        r"(?i)\\+Users\\+([^\\/:*?\"<>|\s]+)")))
    p.append(("identities", "USER", re.compile(
        r"(?<![\w/])/(?:home|Users)/([A-Za-z0-9._\-]{2,})")))
    # user / username / login / account key=value pairs. `usr[_-]?name` covers
    # LEEF's usrName= (QRadar), bare `usr` SonicWALL, `target` Trend Micro CEF;
    # CEF's suser=/duser= match via the bare "user". The optional quote before
    # the separator covers JSON keys ("AccountName":"j.smith"); the space in
    # the key covers Symantec EP's "User name:"; `identity` covers Meraki.
    # `@` in the value keeps Cisco AMP's "user":"j.smith@WS07" in one token.
    p.append(("identities", "USER", re.compile(
        r"(?i)(?:user(?:[ _-]?name|[_-]?id)?|usr[_-]?name|usr|login"
        r"|account(?:[ _-]?name)?|uid|identity|target|sAMAccountName)"
        r"[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9._\\@\-]{2,})")))
    # Domain key=value pairs (M365 Defender "AccountDomain":"acme",
    # Symantec EP "Domain name: ACME", etc.).
    p.append(("identities", "DOMAIN", re.compile(
        r"(?i)(?:account[ _-]?domain|domain[ _-]?name|logon[ _-]?domain)"
        r"[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9._\-]{2,})")))
    # user@IP convention (QRadar SIM Audit "j.smith@10.1.1.100", ESXi).
    p.append(("identities", "USER", re.compile(
        r"\b([A-Za-z][A-Za-z0-9._\-]{1,})@(?=(?:\d{1,3}\.){3}\d)")))
    # XML element style (McAfee ePO EPOEvents, generic agent payloads).
    p.append(("identities", "USER", re.compile(
        r"(?i)<(?:UserName|User|AccountName|TargetUserName)>([^<]+)<")))
    p.append(("identities", "DOMAIN", re.compile(
        r"(?i)<(?:DomainName|Domain|NTDomain)>([^<]+)<")))
    # Azure / Entra ID sign-in JSON: "userDisplayName": "John Smith" and the
    # bare "displayName" inside deviceDetail. "appDisplayName" is deliberately
    # NOT matched (the leading quote anchors the key).
    p.append(("identities", "USER", re.compile(
        r"(?i)\"(?:user[_-]?)?display[_-]?name\"\s*:\s*\"([^\"]+)\"")))
    # Linux auth messages (sshd, su, sudo, pam) and SSO/VPN appliances:
    #   Failed password for invalid user admin from 1.2.3.4
    #   Accepted publickey for jsmith from 10.1.2.3
    #   session opened for user root by jsmith(uid=1000)
    #   sudo: jsmith : TTY=pts/0 ...
    #   User jsmith - Client_ip ... (NetScaler) / User jsmith@1.2.3.4 (ESXi)
    p.append(("identities", "USER", re.compile(
        r"(?i)\b(?:password|publickey|keyboard-interactive\S*) for "
        r"(?:invalid user )?([A-Za-z0-9._\-]{2,}) from\b")))
    p.append(("identities", "USER", re.compile(
        r"(?i)\bsession (?:opened|closed) for user ([A-Za-z0-9._\-]+)")))
    p.append(("identities", "USER", re.compile(
        r"(?i)\bby ([A-Za-z0-9._\-]{2,})\(uid=")))
    p.append(("identities", "USER", re.compile(
        r"(?im)\bsudo(?:\[\d+\])?:[ \t]*([A-Za-z0-9._\-]+)[ \t]*:")))
    p.append(("identities", "USER", re.compile(
        r"(?i)\buser ([A-Za-z0-9._\\\-]{2,})(?=@| -| logged| from)")))
    p.append(("identities", "USER", re.compile(
        r"(?i)\bContext ([A-Za-z0-9._\-]{2,})@")))
    # Apache/nginx combined access log: the authuser field
    #   203.0.113.5 - jsmith [10/Jun/2026:14:23:01 ...
    p.append(("identities", "USER", re.compile(
        r"(?m)^(?:\d{1,3}\.){3}\d{1,3} \S+ ([A-Za-z][A-Za-z0-9._\-]*) \[")))
    # Squid native access log: the username/ident field after the URL,
    #   1581094030.123  245 10.1.2.3 TCP_MISS/200 4521 GET http://… jsmith DIRECT/…
    p.append(("identities", "USER", re.compile(
        r"(?m)^\d{9,10}\.\d{3}[ \t]+\d+[ \t]+(?:\d{1,3}\.){3}\d{1,3}[ \t]+"
        r"[A-Z_]+/\d{3}[ \t]+\d+[ \t]+\w+[ \t]+\S+[ \t]+(\S+)[ \t]+\w+/")))
    # QRadar offense exports: "offense_source": "jsmith" / Offense Source: x
    p.append(("identities", "USER", re.compile(
        r"(?i)[\"']?offense[_\s-]?source[\"']?\s*[=:]\s*[\"']?"
        r"([^\s\"',;]+)")))
    # Network-device style quoted user without a separator, e.g. Cisco
    #   %ASA-6-605005: ... user 'jsmith'   /   F5 APM: Username 'jsmith'
    p.append(("identities", "USER", re.compile(
        r"(?i)\buser(?:name)?\s+'([^'\r\n]{2,})'")))
    # Windows-style DOMAIN\user, incl. dotted domains (ACME.LOCAL\jsmith,
    # vCenter login events). The lookarounds reject matches inside file paths
    # (C:\Windows\System32\cmd.exe would otherwise be shredded into bogus
    # "Windows\System32" users — common in Sysmon Image/CommandLine).
    # (`\\+` tolerates JSON-escaped "ACME\\j.smith".)
    p.append(("identities", "USER", re.compile(
        r"(?<![\\/])\b[A-Za-z0-9][A-Za-z0-9.\-]+\\+[A-Za-z0-9._\-]{2,}\b(?![\\/])")))
    # International phone numbers (E.164-ish, must start with + to keep the
    # false-positive rate near zero in machine logs).
    p.append(("identities", "PHONE", re.compile(
        r"(?<![\w.+-])\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d(?:[ .-]?\d){5,11}\b")))

    # --- network -----------------------------------------------------------
    # MAC addresses.
    p.append(("network", "MAC", re.compile(
        r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")))
    # IPv6: either compressed (contains "::") or a full 8-hextet address.
    # This deliberately avoids matching log timestamps like 10:31:02.
    p.append(("network", "IPV6", re.compile(
        r"(?<![:.\w])(?:"
        r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"          # full 8 groups
        r"|(?:[0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{0,4}::"          # compressed ...
        r"(?:[0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{1,4}"
        r")(?![:.\w])")))
    # IPv4.
    p.append(("network", "IP", re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")))
    # Windows Event Log workstation / computer fields, e.g.
    #   "  Workstation Name:  WS-FINANCE-07" / "Caller Computer Name: PC-042"
    p.append(("network", "HOST", re.compile(
        r"(?im)^[ \t]*(?:Workstation(?: Name)?|Source Workstation"
        r"|Caller Computer Name|Target Server Name|Computer)"
        r"[ \t]*:[ \t]*([^\r\n]+?)[ \t]*$")))
    # Windows XML event exports / Sysmon XML: hostname-bearing <Data> fields
    # and the <Computer> element of the System section.
    p.append(("network", "HOST", re.compile(
        r"(?i)<Data Name=[\"'](?:SourceHostname|DestinationHostname"
        r"|Workstation(?:Name)?|MachineName)[\"']>([^<]+)</Data>")))
    p.append(("network", "HOST", re.compile(
        r"(?i)<Computer>([^<]+)</Computer>")))
    # Syslog header hostname: the token after the classic timestamp, e.g.
    #   Jun 10 14:23:01 fw-edge-01 %ASA-6-302013: ...
    # Also matches after a quote, so syslog lines embedded in JSON strings
    # (Wazuh "full_log", QRadar payloads) are caught too.
    p.append(("network", "HOST", re.compile(
        r"(?m)(?:^|(?<=[\"']))(?:<\d+>)?[A-Z][a-z]{2}[ \t]+\d{1,2}[ \t]"
        r"\d{2}:\d{2}:\d{2}[ \t]+([A-Za-z][A-Za-z0-9._\-]+)\b")))
    # Bare hostnames / computer names given via a key or CLI parameter, e.g.
    #   -ComputerName SRV-DB-02 / hostname=web01 / Server: dc-01
    # These have no TLD, so the FQDN pattern below would miss them.
    p.append(("network", "HOST", re.compile(
        r"(?i)-(?:computer(?:name)?|server|hostname|node|machine)\s+"
        r"[\"']?([A-Za-z0-9][A-Za-z0-9._\-]+)")))
    # Optional quote before the separator covers JSON ("DeviceName":"ws07");
    # the space in the key covers Symantec EP's "Computer name:". The prefixed
    # `host` alternative covers CEF shost=/dhost=/dvchost=/identHostName=. The
    # \b before computer/server/... avoids "SymantecServer:" false positives.
    p.append(("network", "HOST", re.compile(
        r"(?i)(?:[a-z_]*host(?:[ _-]?name)?"
        r"|\b(?:computer|server|node|machine)(?:[ _-]?name)?"
        r"|dev(?:name|id)|device[ _-]?(?:name|id))"
        r"[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9][A-Za-z0-9._\-]+)")))
    # XML element style (McAfee ePO <MachineName>WS07</MachineName>).
    p.append(("network", "HOST", re.compile(
        r"(?i)<(?:MachineName|ComputerName|HostName)>([^<]+)<")))
    # dhcpd: hostname reported in parens — DHCPACK on 10.1.2.55 to
    # 58:40:4e:ab:3d:4e (WS-FIN-07) via eth0
    p.append(("network", "HOST", re.compile(
        r"\(([A-Za-z][\w.\-]*)\) via\b")))
    # UNC paths: \\fileserver01\share\… — masks just the server name. A real UNC
    # path starts a token; inside a JSON-escaped Windows path every separator
    # is a doubled backslash ("C:\\Windows\\System32\\WindowsPowerShell"), so
    # require that the pair is not preceded by a word character or a drive
    # colon — otherwise every path segment looks like a file server.
    p.append(("network", "HOST", re.compile(
        r"(?<![\\:\w])\\\\([A-Za-z0-9][A-Za-z0-9._\-]+)(?=\\)")))
    # Microsoft Defender for Cloud alerts.
    p.append(("network", "HOST", re.compile(
        r"(?i)\"compromised[_-]?entity\"\s*:\s*\"([^\"]+)\"")))
    # Wazuh alert JSON: "agent":{"id":"012","name":"web01-prod"} and the same
    # shape for manager/cluster/node names.
    p.append(("network", "HOST", re.compile(
        r"(?i)\"(?:agent|manager|cluster|node)\"\s*:\s*\{[^{}]*?"
        r"\"name\"\s*:\s*\"([^\"]+)\"")))
    # Quoted agent names: Agent: "web02-prod" / agent_name="x". The lookbehind
    # keeps browser User-Agent headers out.
    p.append(("network", "HOST", re.compile(
        r"(?i)(?<![\w-])agent(?:[ _-]?name)?[\"']?\s*[=:]\s*"
        r"[\"']([^\"'\r\n]+)[\"']")))
    # Wazuh syslog alert header: ... (web02-prod) 10.1.2.5->syscheck ...
    p.append(("network", "HOST", re.compile(
        r"\(([A-Za-z][\w.\-]*)\)[ \t]+(?=(?:\d{1,3}\.){3}\d{1,3}->)")))
    # RFC5424 / ISO-timestamp syslog header (ESXi, vCenter, modern syslog):
    #   2026-06-10T14:23:01.123Z esx01 Hostd: ...
    p.append(("network", "HOST", re.compile(
        r"(?m)^(?:<\d+>\d?[ \t]+)?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
        r"(?:Z|[+-]\d{2}:?\d{2})?[ \t]+([A-Za-z][\w.\-]+)\b")))
    # Cisco Meraki: epoch timestamp then the device name.
    #   1581094030.464317986 MX84_Branch ip_flow_start src=...
    p.append(("network", "HOST", re.compile(
        r"(?m)^\d{10}(?:\.\d+)?[ \t]+([A-Za-z][\w.\-]+)\b")))
    # FQDN / hostnames with a real TLD (filtered against _NOT_TLDS below).
    p.append(("network", "HOST", re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,}\b")))

    return p


# ---------------------------------------------------------------------------
# Protected spans — matched FIRST and never masked.
#
# Security telemetry is full of values that look sensitive and are not: a file
# hash is an IOC an analyst needs to keep (it is the whole question — "is this
# binary known-bad?"), and a vendor's own detector or console URL identifies
# Microsoft, not the customer. Masking those does not protect anyone; it just
# makes the alert unreadable and the answer useless.
#
# These claim their span before any masking pattern runs, so the value survives
# into the text that is sent. Everything here must be justified by "this cannot
# identify the customer, their people, or their infrastructure".
# ---------------------------------------------------------------------------
_KEEP_PATTERNS = [
    # File hashes under an explicit file-hash key. Deliberately NOT a bare
    # `hash=`, which is where credential dumps put NTLM/LM hashes.
    re.compile(r"(?i)\b(?:sha1|sha256|sha512|md5|imphash|authentihash"
               r"|file[_-]?hash|sha256ac)\b[\"']?\s*[=:]\s*[\"']?"
               r"([A-Fa-f0-9]{32,128})\b"),
    # Vendor reference ids: they identify the detection, not the detected.
    re.compile(r"(?i)\b(?:detector|alert|provider[_-]?alert|incident|rule"
               r"|signature|policy|alert[_-]?policy|correlation|request"
               r"|activity|operation)[_-]?id\b[\"']?\s*[=:]\s*[\"']?"
               r"([0-9a-fA-F\-]{8,64})"),
    # MITRE ATT&CK technique / tactic ids.
    re.compile(r"\b(T\d{4}(?:\.\d{3})?|TA\d{4})\b"),
]


_DEFAULT_PATTERNS = _compile_patterns()

# ---------------------------------------------------------------------------
# Per-pattern metadata + user overrides.
#
# _PATTERN_META is aligned 1:1 with the _compile_patterns() order:
#   (id, log source type, what the pattern extracts)
# The id is stable and used as the key in builtin_overrides.json, where the
# settings UI stores edited regexes. An override replaces the default regex
# for that pattern (same position/priority); a broken override is ignored.
# ---------------------------------------------------------------------------
_PATTERN_META: List[Tuple[str, str, str]] = [
    # --- secrets / ids ---
    ("windows-sid", "Windows Event Log",
     "Security identifiers (S-1-5-21-…); short well-known SIDs stay readable"),
    ("azure-resource-id", "Microsoft Azure",
     "\"resourceId\" values (subscription + resource names) as one token"),
    ("credit-card", "Generic secrets", "Credit-card-like 13-16 digit groups"),
    ("api-keys", "Generic secrets",
     "Known API-key shapes (Anthropic, OpenAI, AWS, GitHub, Slack, Google)"),
    ("secret-kv", "Generic secrets",
     "password= / token= / community= values (key=value and JSON)"),
    ("serial-kv", "SonicWALL & devices", "Device serial numbers (sn=, serial=)"),
    ("watchguard-serial", "WatchGuard Fireware",
     "Device serial after the syslog hostname"),
    ("uuid", "Generic secrets", "UUIDs / GUIDs"),
    ("hex-blob", "Generic secrets", "Long hex blobs (hashes, 32+ chars)"),
    # --- identities ---
    ("email", "Generic", "Email addresses"),
    ("ad-dn", "Active Directory",
     "Distinguished names (CN=…,OU=…,DC=…) as one token"),
    ("winxml-user", "Windows XML & Sysmon",
     "<Data Name='TargetUserName'>… and similar user-bearing fields"),
    ("winxml-domain", "Windows XML & Sysmon",
     "<Data Name='TargetDomainName'>… domain fields"),
    ("winevent-user", "Windows Event Log",
     "Indented 'Account Name:' / 'Logon Account:' lines (4624/4625…)"),
    ("winevent-domain", "Windows Event Log",
     "Indented 'Account Domain:' / 'Domain Name:' lines"),
    ("profile-path-user", "File paths (Windows)",
     "Username in C:\\Users\\<name>\\… (only the name is masked)"),
    ("home-path-user", "File paths (Linux/macOS)",
     "Username in /home/<name> and /Users/<name>"),
    ("user-kv", "Generic key=value / JSON / CEF / LEEF",
     "user= username: usrName= usr= account= identity= target= …"),
    ("domain-kv", "Generic key=value / JSON",
     "AccountDomain / Domain name / logon_domain values"),
    ("user-at-ip", "QRadar SIM Audit & VMware", "user@10.0.0.1 actor tokens"),
    ("epoxml-user", "McAfee ePO XML", "<UserName>…</UserName> elements"),
    ("epoxml-domain", "McAfee ePO XML", "<DomainName>…</DomainName> elements"),
    ("displayname-json", "Azure & Entra ID",
     "\"userDisplayName\" / \"displayName\" JSON values"),
    ("sshd-auth-user", "Linux sshd",
     "'Failed password for invalid user X from' / 'Accepted publickey for X'"),
    ("pam-session-user", "Linux su & pam", "'session opened for user X'"),
    ("pam-by-user", "Linux su & pam", "'by X(uid=…)'"),
    ("sudo-user", "Linux sudo", "'sudo: X :' lines"),
    ("user-token", "Appliances (NetScaler, ESXi, ExtremeWare…)",
     "'User X -' / 'User X@…' / 'user X logged|from'"),
    ("netscaler-context", "Citrix NetScaler", "'Context X@ip' tokens"),
    ("access-log-authuser", "Apache & nginx access logs",
     "The authuser field of combined-format access logs"),
    ("squid-user", "Squid Web Proxy",
     "The username/ident field of the native access log"),
    ("qradar-offense-source", "QRadar offenses",
     "\"offense_source\" values from offense exports"),
    ("quoted-user", "Cisco ASA & F5 BIG-IP", "user 'X' / Username 'X'"),
    ("domain-backslash-user", "Windows DOMAIN\\user",
     "DOMAIN\\user incl. dotted domains; skips file paths"),
    ("phone", "Generic", "International phone numbers (+49 …)"),
    # --- network ---
    ("mac", "Generic network", "MAC addresses"),
    ("ipv6", "Generic network", "IPv6 addresses"),
    ("ipv4", "Generic network", "IPv4 addresses"),
    ("winevent-host", "Windows Event Log",
     "Indented 'Workstation Name:' / 'Caller Computer Name:' lines"),
    ("winxml-host", "Windows XML & Sysmon",
     "<Data Name='SourceHostname'>… and similar host fields"),
    ("winxml-computer", "Windows XML & Sysmon", "<Computer>…</Computer>"),
    ("syslog-bsd-host", "Syslog header (BSD)",
     "Hostname after 'Jun 10 14:23:01' style timestamps"),
    ("cli-host-param", "CLI parameters (PowerShell…)",
     "-ComputerName X / -Server X style parameters"),
    ("host-kv", "Generic key=value / JSON / CEF",
     "hostname= shost= dvchost= DeviceName= devname= Computer name: …"),
    ("epoxml-host", "McAfee ePO XML", "<MachineName>…</MachineName> elements"),
    ("dhcpd-host", "Linux DHCP", "Hostname in parens: (WS-FIN-07) via eth0"),
    ("unc-host", "UNC paths", "Server name in \\\\fileserver\\share paths"),
    ("compromised-entity", "Microsoft Defender for Cloud",
     "\"compromisedEntity\" values"),
    ("wazuh-agent-json", "Wazuh",
     "agent/manager/cluster names in alert JSON (\"agent\":{\"name\":…})"),
    ("agent-name-kv", "Wazuh & agent logs",
     "Quoted agent names (Agent: \"x\", agent_name=\"x\"); skips User-Agent"),
    ("wazuh-alert-host", "Wazuh",
     "Agent name in syslog alert headers: (agent) ip->module"),
    ("syslog-iso-host", "Syslog header (ISO) & VMware",
     "Hostname after ISO/RFC5424 timestamps (ESXi, vCenter)"),
    ("meraki-host", "Cisco Meraki", "Device name after the epoch timestamp"),
    ("fqdn", "Generic network", "Fully-qualified domain names / hostnames"),
]

if len(_PATTERN_META) != len(_DEFAULT_PATTERNS):
    raise RuntimeError("_PATTERN_META is out of sync with _compile_patterns()")

OVERRIDES_FILE = paths.data_file("builtin_overrides.json")


def load_overrides() -> Dict[str, str]:
    try:
        with open(OVERRIDES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str) and v}


def save_overrides(overrides: Dict[str, str]) -> None:
    with open(OVERRIDES_FILE, "w", encoding="utf-8") as f:
        json.dump(overrides, f, indent=2)


def _build_patterns() -> List[Tuple[str, str, "re.Pattern"]]:
    """Effective pattern list: defaults with any user overrides applied."""
    overrides = load_overrides()
    out = []
    for (pid, _src, _note), (cat, label, default) in zip(_PATTERN_META,
                                                         _DEFAULT_PATTERNS):
        rx = overrides.get(pid)
        if rx:
            try:
                out.append((cat, label, re.compile(rx)))
                continue
            except re.error:
                pass               # broken override -> fall back to default
        out.append((cat, label, default))
    return out


_PATTERNS = _build_patterns()


def reload_patterns() -> None:
    global _PATTERNS
    _PATTERNS = _build_patterns()


def get_builtin_patterns() -> List[Dict[str, object]]:
    """All built-in patterns with metadata + effective regex, for the UI."""
    overrides = load_overrides()
    out = []
    for (pid, src, note), (cat, label, default) in zip(_PATTERN_META,
                                                       _DEFAULT_PATTERNS):
        out.append({
            "id": pid, "source": src, "note": note,
            "category": cat, "label": label,
            "regex": overrides.get(pid, default.pattern),
            "default_regex": default.pattern,
            "modified": pid in overrides,
        })
    return out


# ---------------------------------------------------------------------------
# User-supplied regex validation.
#
# Saved patterns are not run once — they run on *every* mask call, forever. A
# pattern with catastrophic backtracking (the classic `(a+)+$`) therefore does
# not cause a transient hiccup: it wedges every future analysis, and the leak
# guard with it, until somebody hand-edits the JSON. That is worth spending a
# subprocess on at save time.
#
# The check has to run out-of-process because `re` holds the GIL while it
# backtracks: a thread could not be timed out, it would freeze the server.
# ---------------------------------------------------------------------------
MAX_REGEX_LENGTH = 500
REGEX_CHECK_SECONDS = 2.0

# Exponential backtracking only shows itself on input the pattern almost
# matches, so generic probes are not enough: `(x+x+)+y` is instant against a
# run of "a" and pathological against a run of "x". Probes are therefore built
# from the literal characters of the pattern under test, plus a few generic
# shapes for patterns written entirely with character classes.
#
# This is a best-effort trap for the common cases, not a proof of safety — no
# cheap check is.
_GENERIC_PROBES = (
    "a" * 42 + "!",
    "0123456789" * 6 + "@",
    "ab" * 24 + ";",
    " " * 40 + "!",
    "2026-06-09 10:31:02 user=jsmith from 10.4.2.19 host=ws07.acme.local",
)


def _probes_for(regex: str) -> tuple:
    """Adversarial inputs tailored to `regex`: a long run of each literal
    character it mentions, which is what makes a nested quantifier blow up."""
    literals = []
    for ch in regex:
        if ch.isalnum() and ch not in literals:
            literals.append(ch)
        if len(literals) >= 6:
            break
    tailored = [ch * 40 + "!" for ch in literals]
    tailored += ["".join(literals) * 12 + "!"] if len(literals) > 1 else []
    return tuple(tailored) + _GENERIC_PROBES

_PROBE_SCRIPT = """
import re, sys
pattern = re.compile(sys.argv[1])
for probe in sys.argv[2:]:
    pattern.search(probe)
"""


def validate_user_regex(regex: str) -> str:
    """Return `regex` if it is safe to persist, else raise ValueError.

    Rejects patterns that do not compile, that are absurdly long, or that take
    too long against short adversarial inputs."""
    regex = (regex or "").strip()
    if not regex:
        raise ValueError("The pattern is empty.")
    if len(regex) > MAX_REGEX_LENGTH:
        raise ValueError(
            f"Pattern is {len(regex)} characters; the limit is "
            f"{MAX_REGEX_LENGTH}.")
    try:
        re.compile(regex)
    except re.error as e:
        raise ValueError(f"Not a valid regular expression: {e}")

    import subprocess
    import sys
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _PROBE_SCRIPT, regex, *_probes_for(regex)],
            capture_output=True, timeout=REGEX_CHECK_SECONDS)
    except subprocess.TimeoutExpired:
        raise ValueError(
            "This pattern takes too long to evaluate — it backtracks "
            "catastrophically on ordinary input, and saving it would hang "
            "every future analysis. Avoid nested quantifiers such as (a+)+.")
    except OSError:
        return regex          # cannot spawn a checker; do not block the save
    if proc.returncode != 0:
        raise ValueError("Not a valid regular expression.")
    return regex


def set_builtin_pattern(pattern_id: str, regex: str) -> None:
    """Override a built-in pattern's regex (persists to OVERRIDES_FILE).
    Raises ValueError for an unknown id or an unsafe/invalid regex."""
    regex = validate_user_regex(regex)
    default = None
    for (pid, _src, _note), (_cat, _label, d) in zip(_PATTERN_META,
                                                     _DEFAULT_PATTERNS):
        if pid == pattern_id:
            default = d.pattern
            break
    if default is None:
        raise ValueError(f"No such pattern: {pattern_id}")
    re.compile(regex)              # validate; raises re.error
    overrides = load_overrides()
    if regex == default:
        overrides.pop(pattern_id, None)
    else:
        overrides[pattern_id] = regex
    save_overrides(overrides)
    reload_patterns()


def reset_builtin_pattern(pattern_id: str) -> None:
    """Drop the override for a pattern, restoring its default regex."""
    overrides = load_overrides()
    overrides.pop(pattern_id, None)
    save_overrides(overrides)
    reload_patterns()


# ---------------------------------------------------------------------------
# User-defined persistent patterns.
#
# Stored in custom_patterns.json next to the app, one {"label", "regex"} per
# entry. They are loaded for every mask run, so a pattern added once keeps
# working for every log pasted later. If a regex has a capture group, only the
# group is masked (key=value style); otherwise the whole match is.
# ---------------------------------------------------------------------------
PATTERNS_FILE = paths.data_file("custom_patterns.json")


def load_custom_patterns() -> List[Dict[str, str]]:
    try:
        with open(PATTERNS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return [p for p in data
            if isinstance(p, dict) and p.get("regex") and p.get("label")]


def save_custom_patterns(patterns: List[Dict[str, str]]) -> None:
    with open(PATTERNS_FILE, "w", encoding="utf-8") as f:
        json.dump(patterns, f, indent=2)


def _pattern_label(label: str) -> str:
    """Normalize a user label to the [LABEL_n] placeholder alphabet."""
    cleaned = re.sub(r"[^A-Z0-9]", "", label.upper())
    return cleaned or "CUSTOM"


# ---------------------------------------------------------------------------
# CSV-aware masking (QRadar offense exports, SIEM CSV exports in general).
#
# CSV data is positional: a row carries bare usernames / hostnames / network
# names with no key=value context for the regex patterns to anchor on. When
# the text looks like a CSV with a header row, columns whose header names
# indicate sensitive content are masked cell-by-cell.
# ---------------------------------------------------------------------------
# Header-name fragments that mark a column as NOT maskable (free text handled
# by the normal patterns, or non-sensitive metadata).
_CSV_EXCLUDE = ("count", "date", "time", "duration", "description", "notes",
                "reason", "type", "code", "magnitude", "severity",
                "credibility", "relevance", "status", "category")
# Header-name fragments -> placeholder label, checked in this order.
_CSV_USER_KEYS = ("user", "offensesource", "assigned", "owner", "analyst",
                  "createdby", "closedby", "actor")
_CSV_DOMAIN_KEYS = ("domain",)
_CSV_HOST_KEYS = ("host", "device", "machine", "computer", "asset",
                  "attacker", "target", "source", "destination", "network",
                  "ip")

_HEADERISH = re.compile(r"^[A-Za-z][\w .\-]{0,60}$")
_FULL_IP = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_FULL_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _csv_column_label(header: str):
    h = re.sub(r"[^a-z]", "", header.lower())
    if not h or any(x in h for x in _CSV_EXCLUDE):
        return None
    if any(x in h for x in _CSV_USER_KEYS):
        return "USER"
    if any(x in h for x in _CSV_DOMAIN_KEYS):
        return "DOMAIN"
    if any(x in h for x in _CSV_HOST_KEYS):
        return "HOST"
    return None


def _split_cells(line: str, delim: str):
    """Yield (start, end, value) per cell, honouring double-quoted cells.
    For quoted cells the span excludes the quotes themselves."""
    out = []
    i, n = 0, len(line)
    while i <= n:
        if i < n and line[i] == '"':
            j = i + 1
            while j < n:
                if line[j] == '"':
                    if j + 1 < n and line[j + 1] == '"':
                        j += 2
                        continue
                    break
                j += 1
            out.append((i + 1, j, line[i + 1:j]))
            k = line.find(delim, j)
            i = (k + len(delim)) if k != -1 else n + 1
        else:
            k = line.find(delim, i)
            end = n if k == -1 else k
            out.append((i, end, line[i:end]))
            i = (k + len(delim)) if k != -1 else n + 1
    return out


def _csv_spans(text: str):
    """Spans (start, end, value, label) for sensitive cells of a CSV export.
    Returns [] unless the first line convincingly looks like a header row."""
    lines = text.split("\n")
    if len(lines) < 2:
        return []
    header = lines[0].rstrip("\r")
    delim = "\t" if header.count("\t") > header.count(",") else ","
    if header.count(delim) < 3:
        return []
    cells = _split_cells(header, delim)
    headerish = sum(1 for _, _, v in cells if _HEADERISH.match(v.strip()))
    if headerish < 0.8 * len(cells):       # e.g. a comma-separated log line
        return []
    labels = [_csv_column_label(v.strip()) for _, _, v in cells]
    if not any(labels):
        return []
    spans = []
    offset = len(lines[0]) + 1
    for line in lines[1:]:
        row = line.rstrip("\r")
        if row.strip():
            for idx, (s, e, _val) in enumerate(_split_cells(row, delim)):
                if idx >= len(labels):
                    break
                label = labels[idx]
                if not label:
                    continue
                while s < e and row[s] in " \t":
                    s += 1
                while e > s and row[e - 1] in " \t":
                    e -= 1
                v = row[s:e]
                if not v:
                    continue
                # Plain IPs / emails are left to their own patterns so they
                # keep the more precise IP / EMAIL labels.
                if _FULL_IP.fullmatch(v) or _FULL_EMAIL.fullmatch(v):
                    continue
                spans.append((offset + s, offset + e, v, label))
        offset += len(line) + 1
    return spans


def _accept(label: str, value: str) -> bool:
    """Reject false positives before we commit to masking a match."""
    v = value.strip()
    if not v:
        return False
    if label in ("USER", "DOMAIN", "HOST") and v.lower() in _WINDOWS_BUILTIN_VALUES:
        return False
    # NT AUTHORITY\SYSTEM, NT SERVICE\TrustedInstaller, BUILTIN\Administrators…
    if label == "USER" and "\\" in v \
            and v.lower().split("\\", 1)[0] in _BUILTIN_DOMAIN_PREFIXES:
        return False
    # Numeric values (uid=1000, domainInfo=0) identify nothing on their own.
    if label in ("USER", "DOMAIN") and v.isdigit():
        return False
    # Computer accounts like "WS-FINANCE-07$" ARE customer data; only the bare
    # placeholder values above are skipped.
    if label == "HOST":
        lower = v.lower()
        if lower in _DOMAIN_ALLOWLIST or lower in _NOT_HOSTS:
            return False
        if v.isdigit():          # "localhost:8080" must not mask the port
            return False
        tld = lower.rsplit(".", 1)[-1]
        if "." in lower and tld in _NOT_TLDS:
            return False
        # API/type namespaces: "#microsoft.graph.security.deviceEvidence".
        # A camelCase final label is never a TLD, while "Corp.Local" (capital
        # first letter) and "CORP.LOCAL" are ordinary Windows domains.
        raw_tld = v.rsplit(".", 1)[-1]
        if "." in v and any(c.isupper() for c in raw_tld[1:]) \
                and any(c.islower() for c in raw_tld):
            return False
    # Loopback identifies no one — every host is 127.0.0.1 to itself — and
    # masking it removes the very thing that says "this was local".
    if label in ("IP", "IPV6"):
        try:
            import ipaddress
            addr = ipaddress.ip_address(v.strip("[]"))
            if addr.is_loopback or addr.is_unspecified:
                return False
        except ValueError:
            pass
    # sudo logs say PWD=/home/jsmith meaning the working directory, not a
    # password; filesystem paths are handled by the profile-path patterns.
    if label == "SECRET" and v.startswith("/"):
        return False
    if label == "CC":
        digits = re.sub(r"[ -]", "", v)
        if not (13 <= len(digits) <= 16):
            return False
    return True


def _exact_known_pattern(value: str) -> "re.Pattern":
    """Exact-match pattern for a known value, with word boundaries on the
    alphanumeric edges so short values never mangle the inside of other
    tokens (a value "0" must not match the zeros of every timestamp)."""
    pat = re.escape(value)
    if value and (value[0].isalnum() or value[0] == "_"):
        pat = r"(?<!\w)" + pat
    if value and (value[-1].isalnum() or value[-1] == "_"):
        pat = pat + r"(?!\w)"
    return re.compile(pat)


def mask(text: str, enabled: List[str],
         custom_terms: List[str] = None,
         custom_patterns: List[Dict[str, str]] = None,
         base_mapping: Dict[str, str] = None,
         base_counters: Dict[str, int] = None) -> Tuple[str, Dict[str, str]]:
    """
    Return (masked_text, mapping) where mapping maps placeholder -> real value.

    `enabled` is the list of active category keys (subset of CATEGORIES).
    `custom_terms` are exact strings to always mask (case-insensitive), e.g.
    server names or codenames that no generic pattern can safely infer. They are
    matched first, so they win over the regex categories.
    `custom_patterns` are user-defined {"label", "regex"} dicts (see
    load_custom_patterns); they rank between custom terms and the built-ins
    and are always active regardless of `enabled`.
    `base_mapping` is the placeholder->real mapping of an ongoing conversation:
    every known real value is re-masked with its existing placeholder (even
    where no generic pattern would match it, e.g. a bare username typed in a
    follow-up question), new values continue the numbering, and the returned
    mapping is cumulative.
    `base_counters` sets per-label numbering floors on top of what
    `base_mapping` implies. The entity vault uses this so that a forgotten
    entity's number is retired: a new value can never inherit an old alias.
    """
    enabled_set = set(enabled)

    patterns = list(_PATTERNS)
    # User-defined persistent regexes, above the built-ins. A regex that fails
    # to compile is skipped rather than breaking the whole mask run.
    for cp in reversed(custom_patterns or []):
        try:
            compiled = re.compile(cp["regex"])
        except re.error:
            continue
        patterns.insert(0, ("custom", _pattern_label(cp["label"]), compiled))
    # Per-request patterns for the user's custom terms, highest priority first.
    # Ascending length + insert(0) puts the LONGEST term first, so
    # "SRV-DB-02" wins over a substring term like "SRV".
    for term in sorted({t.strip() for t in (custom_terms or []) if t.strip()},
                       key=len):
        patterns.insert(0, ("custom", "CUSTOM",
                            re.compile(re.escape(term), re.IGNORECASE)))
    # Values already masked earlier in the conversation: highest priority and
    # exact-match, reusing the label from their existing placeholder.
    for ph, real in sorted((base_mapping or {}).items(),
                           key=lambda kv: len(kv[1])):
        if not real:
            continue
        m = re.fullmatch(r"\[([A-Z0-9]+)_\d+\]", ph)
        patterns.insert(0, ("known", m.group(1) if m else "CUSTOM",
                            _exact_known_pattern(real)))

    # Collect non-overlapping spans to replace: (start, end, real_value, label).
    spans: List[Tuple[int, int, str, str]] = []
    # Which character positions are already claimed by an earlier (higher
    # priority) pattern. A bitmap rather than a list of spans: a big log yields
    # tens of thousands of matches, and checking each one against every span
    # taken so far is quadratic — that alone took masking of a 0.5 MB log from
    # sub-second to minutes.
    claimed = bytearray(len(text))

    def overlaps(s: int, e: int) -> bool:
        return claimed.find(1, s, e) >= 0

    def take(s: int, e: int) -> None:
        claimed[s:e] = b"\x01" * (e - s)

    # Protected spans first: file hashes, vendor reference ids and ATT&CK ids
    # claim their span and are never masked, so no later pattern can take them
    # (see _KEEP_PATTERNS for why each one is safe to keep).
    for keep in _KEEP_PATTERNS:
        for m in keep.finditer(text):
            ks, ke = (m.start(1), m.end(1)) if m.lastindex else (m.start(), m.end())
            if not overlaps(ks, ke):
                take(ks, ke)

    # CSV exports first: whole sensitive cells (bare usernames, network and
    # device names that no regex could anchor on) claim their spans before
    # the generic patterns can partially match inside them.
    csv_cells = set()
    for s, e, real, label in _csv_spans(text):
        if not _accept(label, real):
            continue
        if overlaps(s, e):
            continue
        take(s, e)
        spans.append((s, e, real, label))
        csv_cells.add((label, real))
    # Re-mask CSV cell values wherever else they appear (e.g. inside free-text
    # description columns) with the same label, so the same value gets the
    # same placeholder across the whole export. Very short values are masked
    # in their cells only — propagating them is too false-positive-prone.
    for label, real in sorted(csv_cells, key=lambda lr: len(lr[1])):
        if len(real) < 3:
            continue
        patterns.insert(0, ("known", label, _exact_known_pattern(real)))

    for category, label, pattern in patterns:
        if category not in ("custom", "known") and category not in enabled_set:
            continue
        for m in pattern.finditer(text):
            # If the pattern captured a group (key=value style), mask the group.
            if m.lastindex:
                s, e = m.start(m.lastindex), m.end(m.lastindex)
            else:
                s, e = m.start(), m.end()
            real = text[s:e]
            if not _accept(label, real):
                continue
            if overlaps(s, e):
                continue
            take(s, e)
            spans.append((s, e, real, label))

    # Assign stable placeholders. Same real value -> same placeholder.
    # Seed from the conversation's existing mapping so placeholders stay
    # consistent across turns and numbering continues where it left off.
    mapping: Dict[str, str] = {}              # placeholder -> real
    reverse: Dict[Tuple[str, str], str] = {}  # (label, real) -> placeholder
    counters: Dict[str, int] = {}
    for ph, real in (base_mapping or {}).items():
        mapping[ph] = real
        m = re.fullmatch(r"\[([A-Z0-9]+)_(\d+)\]", ph)
        if m:
            reverse[(m.group(1), real)] = ph
            counters[m.group(1)] = max(counters.get(m.group(1), 0),
                                       int(m.group(2)))
    for label, n in (base_counters or {}).items():
        try:
            counters[label] = max(counters.get(label, 0), int(n))
        except (TypeError, ValueError):
            continue

    # Two passes over the spans, for two different reasons.
    #
    # 1. Numbering, walking backwards from the end of the text — this is the
    #    order placeholders have always been assigned in, and callers (and the
    #    vault) depend on which occurrence becomes _1.
    spans.sort(key=lambda x: x[0], reverse=True)
    placed: List[Tuple[int, int, str]] = []
    for s, e, real, label in spans:
        key = (label, real)
        placeholder = reverse.get(key)
        if placeholder is None:
            counters[label] = counters.get(label, 0) + 1
            placeholder = f"[{label}_{counters[label]}]"
            reverse[key] = placeholder
            mapping[placeholder] = real
        placed.append((s, e, placeholder))

    # 2. Rebuilding, forwards, by joining the gaps between spans. Slicing the
    #    whole text once per replacement (out[:s] + ph + out[e:]) copies the
    #    entire log for every match — 60k matches in a 2 MB file meant tens of
    #    gigabytes of copying. Spans never overlap, so a single pass works.
    placed.reverse()                      # ascending by start position
    pieces: List[str] = []
    last = 0
    for s, e, placeholder in placed:
        pieces.append(text[last:s])
        pieces.append(placeholder)
        last = e
    pieces.append(text[last:])

    return "".join(pieces), mapping


def unmask(text: str, mapping: Dict[str, str]) -> str:
    """Replace every placeholder in `text` with its real value."""
    if not mapping:
        return text
    # Longest placeholder first avoids any partial-overlap surprises.
    for placeholder in sorted(mapping, key=len, reverse=True):
        text = text.replace(placeholder, mapping[placeholder])
    return text
