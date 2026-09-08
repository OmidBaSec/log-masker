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

import base64
import binascii
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
    "identities": "Usernames, emails, person names, groups, organisations",
    "network": "Domains, hostnames, IPs, MAC addresses, cloud resources",
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
    # systemd unit suffixes and cron periods -- "session-42.scope",
    # "cron.hourly", "nginx.service". Dotted like a host, named like a unit.
    "scope", "service", "socket", "target", "timer", "mount", "slice",
    "swap", "automount", "hourly", "daily", "weekly", "monthly", "rules",
    "list", "repo", "spec", "lock", "pid", "sock", "old", "orig", "rpmnew",
}

# Tokens that sit where a syslog hostname would but are really log levels,
# plus path components that look like UNC server names in JSON-escaped paths.
_NOT_HOSTS = {
    "info", "warn", "warning", "error", "err", "debug", "notice", "trace",
    "fatal", "crit", "critical", "alert", "emerg", "panic", "audit", "verbose",
    "users", "windows", "system32", "programdata", "program files", "temp",
    "tcp", "udp", "ssl", "tls", "np", "lpc",
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
    # Built-in groups, as "-Identity" and ACL output name them.
    "domain users", "domain admins", "domain computers", "domain controllers",
    "enterprise admins", "schema admins", "authenticated users", "everyone",
    "administrators", "remote desktop users", "backup operators",
    "account operators", "server operators", "print operators", "power users",
    # Unix / Linux daemon accounts. Sysmon for Linux reports these as the User
    # of half the process and network events on a normal host; they ship with
    # the distribution and identify nobody. "root" is already listed above.
    "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news",
    "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody",
    "nogroup", "systemd-network", "systemd-resolve", "systemd-timesync",
    "messagebus", "syslog", "sshd", "postfix", "chrony", "ntp", "dbus",
    "polkitd", "rpc", "rpcuser", "nfsnobody", "apache", "nginx", "mysql",
    "postgres", "redis", "tss", "sssd", "colord", "avahi", "cups", "tcpdump",
    "usbmux", "_apt", "snapd", "kernoops", "landscape", "pollinate", "sshd_t",
}

# Directory names that turn up on the left or right of a backslash inside a
# Windows path. A space in a path ("C:\Program Files\Acme Suite\agent.exe") is
# what lets the DOMAIN\user pattern start half way through one and read
# "Files\Acme" as an account: the lookbehind only rejects the first position.
_PATH_WORDS = {
    "files", "documents", "desktop", "downloads", "pictures", "videos",
    "music", "favorites", "appdata", "local", "locallow", "roaming", "temp",
    "tmp", "windows", "winnt", "system32", "syswow64", "programdata",
    "program", "inetpub", "wwwroot", "drivers", "config", "microsoft",
    "common", "shared", "bin", "lib", "usr", "var", "etc", "opt", "srv",
}

_SHORT_SID = re.compile(r"(?i)S-1-\d+(?:-\d+){0,3}")

# A file name on the right of the backslash says the same thing.
_PATH_FILE_EXT = re.compile(
    r"(?i)\.(?:exe|dll|sys|drv|ocx|cpl|scr|com|msi|msu|cab|inf|ini|config"
    r"|ps1|psm1|psd1|vbs|vbe|js|jse|wsf|bat|cmd|sh|py|jar"
    r"|log|txt|xml|json|csv|dat|db|tmp|zip|7z|rar|lnk)$")

# Well-known SaaS applications and cloud services. When a SaaS audit log names
# the application an action happened in ("appName":"Box"), that names the
# vendor, not the customer -- and it is usually the very thing the alert is
# about, so masking it makes the event unreadable for no protection.
_SAAS_APP_ALLOWLIST = {
    "box", "dropbox", "salesforce", "workday", "servicenow", "slack", "zoom",
    "github", "gitlab", "jira", "confluence", "atlassian", "okta", "onelogin",
    "duo", "docusign", "jumpcloud", "proofpoint", "qualys", "cribl",
    "office 365", "microsoft 365", "sharepoint", "sharepoint online",
    "onedrive", "onedrive for business", "exchange", "exchange online",
    "microsoft teams", "teams", "outlook", "gmail", "google drive",
    "google workspace", "aws", "amazon web services", "azure", "gcp",
    "google cloud", "dynamics 365", "power bi", "power apps", "power automate",
    "zendesk", "hubspot", "netsuite", "sap", "oracle", "tableau", "snowflake",
    "databricks",
}

# DOMAIN\user matches whose "domain" part is really a built-in prefix
# (NT AUTHORITY\SYSTEM, NT SERVICE\TrustedInstaller, BUILTIN\Administrators).
_BUILTIN_DOMAIN_PREFIXES = {"authority", "service", "builtin"}


# Suffixes that make a dotted name inside a filesystem path a real host rather
# than a file or a directory. Deliberately short: the cost of missing one is a
# domain that is still masked everywhere else it appears in the paste and
# propagated back into the path from there, while the cost of being generous
# is "/etc/cron.hourly" coming out redacted.
_PATH_DOMAIN_SUFFIXES = (
    "com", "net", "org", "io", "co", "uk", "de", "fr", "nl", "eu", "us",
    "ca", "au", "jp", "cn", "ru", "ch", "se", "no", "dk", "fi", "it", "es",
    "pl", "be", "at", "ie", "nz", "za", "br", "in", "info", "biz", "gov",
    "edu", "mil", "int", "local", "lan", "loc", "internal", "corp", "intra",
    "intranet", "ad", "home", "priv", "private", "localdomain",
)


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
    # --- AWS, GCP and SaaS audit logs -------------------------------------
    # AWS ARNs name the account and the principal or resource inside it, so
    # the whole value is masked as one token: masking only the embedded
    # account number would leave "…:user/j.smith" in plain sight. The
    # 12-digit account field is required, which deliberately spares vendor
    # product ARNs (arn:aws:securityhub:eu-west-1::product/aws/guardduty) --
    # those name the detector, not the customer.
    p.append(("network", "ARN", re.compile(
        r"(?i)\barn:aws[a-z\-]*:[a-z0-9\-]*:[a-z0-9\-]*:\d{12}:"
        r"[^\s\"',\\]+")))
    # AWS Config and GCP audit logs carry the customer's resource path under
    # "resourceName" ("projects/acme-prod/zones/…/instances/web-prod-01").
    p.append(("network", "RESOURCE", re.compile(
        r"(?i)\"resource[_-]?name\"\s*:\s*\"([^\"]+)\"")))
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
    # AWS unique ids: IAM principals (AIDA/AROA/AGPA/AIPA), managed policies
    # (ANPA/ANVA) and temporary STS access keys (ASIA). They hold no secret
    # material, but they name the principal behind every CloudTrail event.
    p.append(("secrets", "KEYID", re.compile(
        r"\bA(?:IDA|ROA|GPA|IPA|NPA|NVA|SIA|BIA|CCA)[A-Z0-9]{16,}\b")))
    # SaaS object ids that name a tenant's user, app or integration:
    # Okta (00u…, 00g…, 0oa…) and Duo Security (DU…, DI…, DA…, DG…).
    p.append(("secrets", "KEYID", re.compile(
        r"\b(?:(?:00[ugo]|0oa)[A-Za-z0-9]{15,}|D[UIAG][A-Z0-9]{18})\b")))
    # 24-character object ids under an id key: Atlassian account ids,
    # JumpCloud / Mongo-style ObjectIds. Too short for the hex-blob pattern
    # further down and meaningless out of context, so the key is required.
    p.append(("secrets", "KEYID", re.compile(
        r"(?i)\"[a-z_]*id\"\s*:\s*\"([0-9a-z]{24})\"")))
    # Cloud / SaaS account and tenant numbers. AWS account ids are exactly
    # 12 digits; OneLogin, Zoom and Dynamics 365 use shorter integers. Only
    # masked next to an explicit key -- a bare integer identifies nothing.
    p.append(("secrets", "ACCTID", re.compile(
        r"(?i)\b[a-z_]*(?:account|tenant|customer|subscriber"
        r"|org(?:anization)?)[_-]?id\"?\s*[=:]\s*\"?(\d{4,20})\b")))
    # Numeric user ids of SaaS audit logs ("user_id":123456,
    # "actor_user_id":654321). The generic user patterns deliberately skip
    # bare numbers; inside a tenant these do identify a person.
    p.append(("secrets", "ACCTID", re.compile(
        r"(?i)\"[a-z_]*user[_-]?id\"\s*:\s*(\d{4,20})\b")))
    # Bearer / token / password / SNMP-community key=value pairs -> mask the
    # value only. The optional quote before the separator covers JSON keys:
    #   "password": "hunter2"
    p.append(("secrets", "SECRET", re.compile(
        r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|auth|community"
        r"|client[_-]?id)"
        r"[\"']?\s*[=:]\s*[\"']?([^\s\"',;]+)")))
    # Plaintext credentials as PowerShell writes them: the literal handed to
    # ConvertTo-SecureString, a -Password/-AccessToken argument, and the
    # positional password of "net use ... /user:DOM\\svc <password>". None of
    # these is a key=value pair, so the generic secret pattern above cannot see
    # them — and a script-block log (event 4104) records the password verbatim.
    p.append(("secrets", "SECRET", re.compile(
        r"(?i)ConvertTo-SecureString\s+(?:-(?:String|AsPlainText)\s+)*"
        r"[\"']([^\"'\r\n]+)[\"']")))
    p.append(("secrets", "SECRET", re.compile(
        r"(?i)(?<![\w-])--?(?:password|passwd|pwd|accesstoken|api[_-]?key"
        r"|token|secret|clientsecret|sharedkey|passphrase)[ \t]+"
        r"[\"']?([^\s\"',;]+)")))
    p.append(("secrets", "SECRET", re.compile(
        r"(?i)/user:\S+[ \t]+([^\s\"',;<]+)")))
    # "-p" names the service-principal secret in this one command and a port
    # in plenty of others, so it is read here and nowhere else.
    p.append(("secrets", "SECRET", re.compile(
        r"(?i)\baz[ \t]+login\b[^\r\n]*?[ \t]-p[ \t]+[\"']?([^\s\"']+)")))
    # "Authorization = \"Bearer eyJ…\"" in an -Headers hashtable.
    p.append(("secrets", "SECRET", re.compile(
        r"(?i)\bBearer[ \t]+([A-Za-z0-9._\-]{16,})")))
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
    # --- Sysmon (Windows & Linux) -----------------------------------------
    # Sysmon and Sysmon for Linux emit the same field names in three shapes:
    # the Event Viewer "Field: value" render, forwarded XML (<Data Name='…'>)
    # and JSON from a shipper. They are read here, ahead of every generic
    # key=value pattern, so the WHOLE value is claimed as one placeholder --
    # left to the generic user pattern, "ParentUser: ACME\a.karimi" can match
    # only as far as "ACME\a." and the rest of the name is sent in clear.
    #
    # Windows reports User as DOMAIN\account, Linux as a bare login name; both
    # are one value here. SourceUser / TargetUser are the two sides of a
    # ProcessAccess (event 10) and of Linux events 11 and 23.
    p.append(("identities", "USER", re.compile(
        r"(?im)^[ \t]*(?:Parent|Source|Target|Original)?User"
        r"[ \t]*:[ \t]*([^\r\n]+?)[ \t]*$")))
    p.append(("identities", "USER", re.compile(
        r"(?i)<Data Name=[\"'](?:Parent|Source|Target|Original)?User[\"']>"
        r"([^<]+)</Data>")))
    p.append(("identities", "USER", re.compile(
        r"(?i)\"(?:Parent|Source|Target|Original)User\"\s*:\s*\"([^\"]+)\"")))
    # Machine names either side of a network connection (event 3) and the name
    # asked for in a DNS query (event 22). QueryName is masked like any other
    # hostname: an internal name ("dc01.acme.lan") is exactly what must not
    # leave, and the FQDN pattern already treats external ones the same way.
    p.append(("network", "HOST", re.compile(
        r"(?im)^[ \t]*(?:Source|Destination)Hostname"
        r"[ \t]*:[ \t]*([^\r\n]+?)[ \t]*$")))
    p.append(("network", "HOST", re.compile(
        r"(?im)^[ \t]*QueryName[ \t]*:[ \t]*([^\r\n]+?)[ \t]*$")))
    p.append(("network", "HOST", re.compile(
        r"(?i)<Data Name=[\"'](?:Source|Destination)Hostname[\"']>"
        r"([^<]+)</Data>")))
    p.append(("network", "HOST", re.compile(
        r"(?i)<Data Name=[\"']QueryName[\"']>([^<]+)</Data>")))
    p.append(("network", "HOST", re.compile(
        r"(?i)\"(?:(?:Source|Destination)Hostname|QueryName)\"\s*:\s*"
        r"\"([^\"]+)\"")))
    # --- SaaS / cloud audit logs ------------------------------------------
    # These formats are JSON, with the identity under a vendor-specific key
    # and often a multi-word value ("John Smith", "Acme Payroll App") that
    # the generic key=value patterns further down truncate at the first
    # space. Anchoring on the quoted key and taking the whole quoted value
    # keeps each identity a single placeholder. They sit after the email
    # pattern so an address still gets an [EMAIL_n] alias, not [USER_n].
    #
    # Actor fields: GitHub ("actor"), Jira ("authorKey"), Zoom ("operator"),
    # OneLogin ("actor_user_name"), Power Platform ("createdBy").
    p.append(("identities", "USER", re.compile(
        r"(?i)\"(?:actor|author(?:[_-]?key)?|operator|initiator|principal"
        r"|impersonator|requester|assignee|created[_-]?by|modified[_-]?by"
        r"|updated[_-]?by|closed[_-]?by|deleted[_-]?by|performed[_-]?by"
        r"|[a-z_]*user[_-]?name)\"\s*:\s*\"([^\"]+)\"")))
    # Actor objects: Duo ("user":{"name":…}), JumpCloud ("initiated_by":
    # {"username":…}), Zoom ("participant":{"user_name":…}).
    p.append(("identities", "USER", re.compile(
        r"(?i)\"(?:user|actor|initiated[_-]?by|participant|operator|owner"
        r"|assignee|author|member)\"\s*:\s*\{[^{}]*?"
        r"\"(?:user[_-]?)?name\"\s*:\s*\"([^\"]+)\"")))
    # Group, zone, role and policy names name the customer's own org units
    # and rules: CylancePROTECT zones, Defender rbacGroupName, Okta and
    # JumpCloud groups, Purview and Imperva policy names. Handles both
    # key=value ("Zone Names: (Finance-EU)") and JSON, and takes the whole
    # value so "Domain Admins" stays one token.
    p.append(("identities", "GROUP", re.compile(
        r"(?i)\b(?:[a-z_]*group|zone|policy|role)[ _-]?names?[\"']?\s*[=:]"
        r"[ \t]*[(\"']?([^,;()\"'\r\n\t]{1,120}?)"
        r"(?=[ ]{2,}|\t|\s*[,;)\"'\r\n]|$)")))
    p.append(("identities", "GROUP", re.compile(
        r"(?i)\"(?:department|division|team|business[_-]?unit"
        r"|target[_-]?user[_-]?or[_-]?group[_-]?name)\"\s*:\s*\"([^\"]+)\"")))
    # Jira audit: "objectItem":{"name":"acme-admins","typeName":"GROUP"}.
    p.append(("identities", "GROUP", re.compile(
        r"(?i)\"(?:object[_-]?item|group|team|role)\"\s*:\s*\{[^{}]*?"
        r"\"name\"\s*:\s*\"([^\"]+)\"")))
    # CEF custom string fields are self-describing -- "cs1Label=Policy cs1=…".
    # Imperva SecureSphere puts the customer's policy and application names
    # there, where the key alone ("cs1") tells the generic patterns nothing.
    # The back-reference ties the value to its own label; the bounded lazy
    # gap keeps it linear.
    p.append(("identities", "GROUP", re.compile(
        r"(?i)\bcs(\d)Label=(?:policy|rule|group|department|tenant|site"
        r"|application|app)\b.{0,120}?\bcs\1=([^\s\"']+)")))
    # Organisation / tenant / workspace names: GitHub ("org", "business"),
    # Dynamics 365 ("Organization"), Jira and Zoom tenants.
    p.append(("identities", "ORG", re.compile(
        r"(?i)\"(?:org|organi[sz]ation(?:[_-]?name)?|business(?:[_-]?name)?"
        r"|tenant(?:[_-]?name)?|workspace|company(?:[_-]?name)?"
        r"|customer(?:[_-]?name)?)\"\s*:\s*\"([^\"]+)\"")))
    # Zoom meeting topics and the "operation detail" strings of SaaS admin
    # logs are pure customer business content. Email subjects are
    # deliberately NOT masked: in a phishing case the subject line is the
    # evidence being analyzed, exactly like a file hash.
    p.append(("identities", "SUBJECT", re.compile(
        r"(?i)\"(?:topic|meeting[_-]?topic|operation[_-]?detail"
        r"|session[_-]?name)\"\s*:\s*\"([^\"]+)\"")))
    # Active Directory distinguished names, e.g.
    #   CN=John Smith,OU=Sales,DC=acme,DC=com
    # Masked as one token; requires 2+ components so a lone "DC=..." in prose
    # is not enough to trigger. Values are lazy so the final component stops
    # at the first whitespace instead of swallowing the rest of the line.
    p.append(("identities", "DN", re.compile(
        r"(?im)\b(?:CN|OU|DC)=[^,;\r\n]+?(?:\s*,\s*(?:CN|OU|DC)=[^,;\r\n]+?)+"
        r"(?=[\s,;\"')\]]|$)")))
    # Windows Security-channel XML exports (the Event Viewer "XML View", and
    # the same events forwarded by WEF or a shipper):
    #   <Data Name='TargetUserName'>jsmith</Data>
    # Sysmon's own fields (User, ParentUser, SourceHostname...) are NOT here:
    # they live in the Sysmon group, which reads them in all three encodings.
    p.append(("identities", "USER", re.compile(
        r"(?i)<Data Name=[\"'](?:TargetUserName|SubjectUserName"
        r"|AccountName|SamAccountName|LogonAccount)[\"']>"
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
        r"(?i)(?:user(?:[ _-]?name|[ _-]?id)?|usr[_-]?name|usr|login"
        r"|account(?:[ _-]?name)?|uid|identity|target|sAMAccountName)"
        r"[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9._\\@\-]{2,})\b(?![ \t]*=)")))
    # Domain key=value pairs (M365 Defender "AccountDomain":"acme",
    # Symantec EP "Domain name: ACME", etc.).
    p.append(("identities", "DOMAIN", re.compile(
        r"(?i)(?:account[ _-]?domain|domain[ _-]?name|logon[ _-]?domain)"
        r"[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9._\-]{2,})")))
    # PowerShell Format-List output — "Get-ADUser -Properties * | fl" and
    # every Exchange/Graph cmdlet print one aligned "Field : value" per line.
    # Bare "Name" is deliberately absent: in Get-Process it is a binary.
    p.append(("identities", "USER", re.compile(
        r"(?im)^[ \t]*(?:DisplayName|GivenName|Surname|FullName"
        r"|PrimaryOwnerName|Manager|EmployeeID|PrincipalName|Alias)"
        r"[ \t]*:[ \t]*([^\r\n]+?)[ \t]*$")))
    p.append(("identities", "USER", re.compile(
        r"(?i)Get-Credential[ \t]+(?:-UserName[ \t]+)?[\"']([^\"'\r\n]+)[\"']")))
    # Microsoft Graph and Exchange filter strings, as -Filter takes them:
    #   Get-MgUser -Filter "displayName eq 'Petra Vogel'"
    p.append(("identities", "USER", re.compile(
        r"(?i)\b(?:displayName|userPrincipalName|mail|givenName|surname"
        r"|samAccountName|onPremisesSamAccountName|windowsLiveID)"
        r"\s+-?eq\s+[\"']([^\"'\r\n]+)[\"']")))
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
        r"(?<![\\/\-.])\b[A-Za-z0-9][A-Za-z0-9.\-]+\\+[A-Za-z0-9._\-]{2,}\b(?![\\/])"
        # "CORP\Domain Users" is a built-in group: match neither half of it
        # here, and let the domain be masked as a domain by itself.
        r"(?!\ +(?:Users|Admins|Computers|Controllers|Operators|Guests)\b)")))
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
        r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")))
    # Windows Event Log workstation / computer fields, e.g.
    #   "  Workstation Name:  WS-FINANCE-07" / "Caller Computer Name: PC-042"
    p.append(("network", "HOST", re.compile(
        r"(?im)^[ \t]*(?:Workstation(?: Name)?|Source Workstation"
        r"|Caller Computer Name|Target Server Name|Computer)"
        r"[ \t]*:[ \t]*([^\r\n]+?)[ \t]*$")))
    # Windows Security-channel XML: the workstation fields of a logon event,
    # and the <Computer> element every Windows XML event carries in <System>.
    p.append(("network", "HOST", re.compile(
        r"(?i)<Data Name=[\"'](?:Workstation(?:Name)?|MachineName)[\"']>"
        r"([^<]+)</Data>")))
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
    # Customer-named cloud and SaaS containers: GitHub repos, GCP projects,
    # S3 buckets, Power Platform environments, Okta and OneLogin application
    # names, Okta target "alternateId". These name the customer's estate as
    # surely as a hostname does. Vendor app names ("appName":"Box") are
    # filtered out by _SAAS_APP_ALLOWLIST rather than by the regex.
    p.append(("network", "ASSET", re.compile(
        r"(?i)\"(?:repo(?:sitory)?(?:[_-]?name)?"
        r"|project(?:[_-]?(?:id|name|number))?"
        r"|environment(?:[_-]?name)?|namespace|bucket(?:[_-]?name)?"
        r"|[a-z_]*app(?:lication)?[_-]?name|service[_-]?name"
        r"|instance[_-]?name|site[_-]?name|alternate[_-]?id"
        r"|source[_-]?file[_-]?name|destination[_-]?file[_-]?name"
        r"|source[_-]?relative[_-]?url)\"\s*:\s*"
        r"\"([^\"]+)\"")))
    # CEF sourceServiceName= (Imperva WAF Gateway names the protected app).
    p.append(("network", "ASSET", re.compile(
        r"(?i)\b(?:source|destination|dest)?service[_-]?name=([^\s\"']+)")))
    # S3 server access logs are positional: the 64-hex bucket-owner canonical
    # id leads the line and the bucket name follows it; the object key
    # follows the REST.<verb>.<resource> operation.
    p.append(("network", "ASSET", re.compile(
        r"(?m)^[0-9a-f]{64}[ \t]+([^\s\[]+)[ \t]+\[")))
    p.append(("network", "ASSET", re.compile(
        r"\bREST\.[A-Z]+\.[A-Z]+[ \t]+(\S+)")))
    # Object paths inside cloud-storage and SharePoint/OneDrive URLs. Only
    # the path is claimed: the hostname is left to the FQDN pattern, so the
    # same tenant host keeps one [HOST_n] alias everywhere it appears.
    p.append(("network", "ASSET", re.compile(
        r"(?i)\.(?:blob|file|queue|table|dfs)\.core\.windows\.net"
        r"(/[^\s\"'?<>]+)")))
    p.append(("network", "ASSET", re.compile(
        r"(?i)s3[.\-][a-z0-9\-]*\.?amazonaws\.com(/[^\s\"'?<>]+)")))
    # SharePoint document paths may contain spaces ("/Shared Documents/…"),
    # so the value runs to the closing quote or end of line.
    p.append(("network", "ASSET", re.compile(
        r"(?i)\.sharepoint\.com(/[^\"'\r\n]*?)(?=[\"'\r\n]|$)")))
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
    # Qualys VM asset exports (XML): <DNS>, <NETBIOS>, <FQDN> elements.
    p.append(("network", "HOST", re.compile(
        r"(?i)<(?:NETBIOS|DNS|DNS_DATA|FQDN)>([^<]+)<")))
    # "logged into host WORKSTATION-88", "connect to server SRV-DB-01" — prose
    # rather than a field, so the keyword alone is not enough: the value must
    # also carry the shape of an asset name. The keyword is case-insensitive,
    # the value deliberately is not, or every "host is" reads as a hostname.
    p.append(("network", "HOST", re.compile(
        r"(?:(?i:host|hostname|computer|machine|workstation|server|device))"
        r"[ \t]+([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+"
        # ... and its domain, if it is written as an FQDN. Without this the
        # span stops at "SRV-SQL-03" and sends ".corp.acme.local" in the clear.
        r"(?:\.[A-Za-z0-9][A-Za-z0-9\-]*)*)\b")))
    # A PowerShell transcript is named after the machine it was taken on:
    #   PowerShell_transcript.WKS-FIN-042.Xy3kR2p1.20260902141233.txt
    p.append(("network", "HOST", re.compile(
        r"(?i)PowerShell_transcript[._]([A-Za-z0-9][A-Za-z0-9\-]+)")))
    # dhcpd: hostname reported in parens — DHCPACK on 10.1.2.55 to
    # 58:40:4e:ab:3d:4e (WS-FIN-07) via eth0
    p.append(("network", "HOST", re.compile(
        r"\(([A-Za-z][\w.\-]*)\) via\b")))
    # UNC paths: \\fileserver01\share\… — masks just the server name. A real UNC
    # path starts a token; inside a JSON-escaped Windows path every separator
    # is a doubled backslash ("C:\\Windows\\System32\\WindowsPowerShell"), so
    # require that the pair is not preceded by a word character or a drive
    # colon — otherwise every path segment looks like a file server. Two to
    # four backslashes so a UNC path that is itself JSON-escaped still
    # matches, and the server may end the token: $env:LOGONSERVER is
    # nothing but \\\\DC01.
    p.append(("network", "HOST", re.compile(
        r"(?:(?<=::)|(?<![:\w]))\\{2,4}([A-Za-z0-9][A-Za-z0-9._\-]+)"
        r"(?=\\|[\s\"',;)\]]|$)")))
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
    # Not when it sits inside a filesystem path: "/etc/cron.hourly" is a
    # directory and "/var/log/syslog.1" a file, neither of them a host. The
    # "//" branch keeps a URL's host, which is also preceded by a slash. A
    # domain that really does appear in a path is still caught wherever else
    # it appears in the paste, and propagated back into the path from there.
    # A real domain inside a path is still a domain -- "/var/www/acme.com" --
    # but only where the suffix is one, which is what tells it apart from
    # "/etc/cron.hourly". Anchored to the slash so it cannot start half way
    # through and mask "corp.com" out of "acme-corp.com".
    p.append(("network", "HOST", re.compile(
        r"(?<=/)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
        r"(?:" + "|".join(_PATH_DOMAIN_SUFFIXES) + r")\b")))
    p.append(("network", "HOST", re.compile(
        # Not mid-token either: a lookbehind that only rejects the first
        # position is dodged by starting at the next label, which is how
        # "/var/www/acme-corp.com" came out as "acme-[HOST_2]".
        r"(?:(?<=//)|(?<![/\\.\-]))"
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
    # Vendor event taxonomies: Okta "eventType":"user.session.start", GitHub
    # "action":"repo.destroy", GCP "methodName":"v1.compute.instances.delete",
    # CloudTrail "eventSource":"signin.amazonaws.com". These dotted lowercase
    # enums are the field that says WHAT HAPPENED, and the FQDN pattern would
    # otherwise mask them as hostnames. The dotted-enum shape is also what
    # separates a vendor API ("serviceName":"compute.googleapis.com") from a
    # customer's own service name, which stays maskable.
    re.compile(r"(?i)\"(?:event[_-]?type|event[_-]?name|event[_-]?source"
               r"|action|operation(?:[_-]?name)?|method[_-]?name"
               r"|service[_-]?name|activity[_-]?type|category[_-]?type)\""
               r"\s*:\s*\"([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)\""),
    # .NET type names and PowerShell variables. "[System.Net.Dns]",
    # "New-Object System.Management.Automation.PSCredential" and "$wc.Proxy"
    # are dotted like a hostname and name nothing but the runtime.
    re.compile(r"\[(?:System|Microsoft|Windows|Net|Automation|PSObject)"
               r"\.[A-Za-z0-9_.\[\]]+\]"),
    re.compile(r"(?i)New-Object[ \t]+(?:-TypeName[ \t]+)?"
               r"([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)"),
    re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+"),
    # PowerShell provider paths: "Microsoft.WSMan.Management\WSMan::localhost",
    # "Microsoft.PowerShell.Core\FileSystem::\\NAS-01\Finance". The provider
    # half names the runtime; what follows "::" does not, and is deliberately
    # left outside the protected span.
    re.compile(r"\b(?:Microsoft|System)\.[A-Za-z0-9_.]+"
               r"(?:\\[A-Za-z0-9_]+)?(?=::)"),
    # --- Sysmon scaffolding (Windows and Linux) ---
    # The XML namespace and the provider GUID of the channel itself. Both are
    # published constants that name Microsoft's schema and the Sysmon driver,
    # the same for every installation on earth, and the GUID would otherwise
    # be masked as a UUID and the namespace URL as a hostname.
    re.compile(r"(?i)\bxmlns(?::\w+)?=[\"']([^\"'\r\n]+)[\"']"),
    re.compile(r"(?i)<Provider\b[^>]{0,200}?Guid=[\"']\{?"
               r"([0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})\}?"),
    # WMI object model (events 19-21): "root\cimv2" is a namespace and
    # "CommandLineEventConsumer.Name" a class, not a domain and a host.
    re.compile(r"(?i)\broot\\{1,4}(?:cimv2|subscription|default|wmi|rsop"
               r"|policy|directory|standardcimv2)"
               r"(?:\\{1,4}[A-Za-z0-9_]+)*"),
    re.compile(r"(?i)\b(?:__[A-Za-z]\w+"
               r"|(?:CommandLine|ActiveScript|LogFile|NTEventLog|SMTP)"
               r"EventConsumer)(?:\.[A-Za-z]\w*)?"),
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
    ("aws-arn", "AWS (CloudTrail, Config, S3, Security Hub)",
     "Full ARNs as one token; vendor product ARNs stay readable"),
    ("cloud-resource-name", "AWS Config & GCP audit",
     "\"resourceName\" project / instance paths as one token"),
    ("credit-card", "Generic secrets", "Credit-card-like 13-16 digit groups"),
    ("api-keys", "Generic secrets",
     "Known API-key shapes (Anthropic, OpenAI, AWS, GitHub, Slack, Google)"),
    ("aws-principal-id", "AWS (CloudTrail, Security Hub)",
     "IAM principal ids and STS temporary keys (AIDA/AROA/ASIA…)"),
    ("saas-object-id", "Okta & Duo Security",
     "Okta object ids (00u…, 0oa…) and Duo integration keys"),
    ("saas-object-id-kv", "Atlassian Jira & JumpCloud",
     "24-character account / object ids under an id key"),
    ("cloud-account-id", "AWS, Dynamics 365, OneLogin",
     "Account / tenant numbers under an explicit key"),
    ("saas-user-id-num", "OneLogin, Zoom, JumpCloud",
     "Numeric user ids (\"user_id\":123456)"),
    ("secret-kv", "Generic secrets",
     "password= / token= / community= values (key=value and JSON)"),
    ("ps-securestring", "PowerShell",
     "The literal passed to ConvertTo-SecureString"),
    ("ps-secret-param", "PowerShell",
     "-Password / -AccessToken / -ApiKey parameter arguments"),
    ("net-use-password", "Windows CLI",
     "The positional password of 'net use ... /user:DOM\\svc <password>'"),
    ("az-login-secret", "Azure CLI",
     "The service-principal secret of 'az login -p ...'"),
    ("bearer-token", "Generic secrets", "Bearer tokens in Authorization values"),
    ("serial-kv", "SonicWALL & devices", "Device serial numbers (sn=, serial=)"),
    ("watchguard-serial", "WatchGuard Fireware",
     "Device serial after the syslog hostname"),
    ("uuid", "Generic secrets", "UUIDs / GUIDs"),
    ("hex-blob", "Generic secrets", "Long hex blobs (hashes, 32+ chars)"),
    # --- identities ---
    ("email", "Generic", "Email addresses"),
    # --- Sysmon ---
    ("sysmon-user", "Sysmon (Windows & Linux)",
     "User / ParentUser / SourceUser / TargetUser lines, whole value"),
    ("sysmon-user-xml", "Sysmon (Windows & Linux)",
     "The same user fields in forwarded XML (<Data Name='ParentUser'>)"),
    ("sysmon-user-json", "Sysmon (Windows & Linux)",
     "The same user fields in shipper JSON (\"ParentUser\": \"…\")"),
    ("sysmon-hostname", "Sysmon (Windows & Linux)",
     "SourceHostname / DestinationHostname of a network connection (event 3)"),
    ("sysmon-dns-query", "Sysmon (Windows & Linux)",
     "QueryName of a DNS query (event 22)"),
    ("sysmon-hostname-xml", "Sysmon (Windows & Linux)",
     "SourceHostname / DestinationHostname in forwarded XML"),
    ("sysmon-dns-query-xml", "Sysmon (Windows & Linux)",
     "QueryName in forwarded XML"),
    ("sysmon-host-json", "Sysmon (Windows & Linux)",
     "Hostname and DNS query fields in shipper JSON"),
    ("saas-actor-kv", "SaaS audit logs (GitHub, Jira, Zoom, OneLogin)",
     "\"actor\" / \"authorKey\" / \"operator\" / \"createdBy\" values"),
    ("saas-actor-object", "Duo Security, JumpCloud, Zoom",
     "Names inside actor objects (\"user\":{\"name\":…})"),
    ("group-name-kv", "CylancePROTECT, M365 Defender, Purview, Imperva",
     "Zone / group / policy / role names (key=value and JSON)"),
    ("org-unit-kv", "Entra ID, Okta, Office 365",
     "Department / division / team / target-group names"),
    ("group-object", "Atlassian Jira audit",
     "Group names inside \"objectItem\":{\"name\":…}"),
    ("cef-custom-label", "Imperva WAF Gateway & CEF",
     "Self-describing CEF custom strings (cs1Label=Policy cs1=…)"),
    ("org-tenant-kv", "GitHub, Dynamics 365, Atlassian Jira",
     "Organisation / tenant / business / workspace names"),
    ("subject-topic-kv", "Zoom & SaaS admin logs",
     "Meeting topics and operation details (email subjects are kept)"),
    ("ad-dn", "Active Directory",
     "Distinguished names (CN=…,OU=…,DC=…) as one token"),
    ("winxml-user", "Windows Event Log (XML)",
     "<Data Name='TargetUserName'>… and the other Security-channel user fields"),
    ("winxml-domain", "Windows Event Log (XML)",
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
    ("get-credential-user", "PowerShell",
     "The account named in Get-Credential \"DOM\\user\""),
    ("graph-filter-user", "Microsoft Graph & Exchange",
     "-Filter \"displayName eq 'X'\" comparisons"),
    ("ps-person-field", "PowerShell Format-List",
     "DisplayName / GivenName / Surname / PrimaryOwnerName lines"),
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
    ("winxml-host", "Windows Event Log (XML)",
     "<Data Name='WorkstationName'>… workstation fields of a logon event"),
    ("winxml-computer", "Windows Event Log (XML)",
     "<Computer>…</Computer>, the host every Windows XML event names"),
    ("syslog-bsd-host", "Syslog header (BSD)",
     "Hostname after 'Jun 10 14:23:01' style timestamps"),
    ("cli-host-param", "CLI parameters (PowerShell…)",
     "-ComputerName X / -Server X style parameters"),
    ("cloud-asset-kv", "GitHub, GCP, AWS, Power Platform, Okta, Office 365",
     "Repos, projects, buckets, environments, apps, SharePoint documents"),
    ("cef-service-name", "Imperva WAF Gateway & CEF",
     "sourceServiceName= protected-application names"),
    ("s3-access-bucket", "AWS S3 server access logs",
     "Bucket name after the owner canonical id"),
    ("s3-access-key", "AWS S3 server access logs",
     "Object key after the REST.<verb>.<resource> operation"),
    ("azure-blob-path", "Azure Storage",
     "Container + object path of blob/file/queue/table URLs"),
    ("s3-url-path", "AWS S3", "Object path of s3…amazonaws.com URLs"),
    ("sharepoint-path", "Office 365 & Purview",
     "Site and document path of SharePoint / OneDrive URLs"),
    ("host-kv", "Generic key=value / JSON / CEF",
     "hostname= shost= dvchost= DeviceName= devname= Computer name: …"),
    ("epoxml-host", "McAfee ePO XML", "<MachineName>…</MachineName> elements"),
    ("qualys-xml-host", "Qualys VM",
     "<DNS> / <NETBIOS> / <FQDN> elements of asset exports"),
    ("host-in-prose", "Generic network",
     "Asset-shaped names after 'host'/'server'/'workstation' in prose"),
    ("ps-transcript-name", "PowerShell",
     "The computer name inside a PowerShell_transcript.<host>.… filename"),
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
    ("path-domain", "File paths",
     "Domains inside a path (/var/www/acme.com), by suffix"),
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
    # JSON Lines is the wire format of most cloud connectors (AWS, Okta,
    # GitHub, Duo…), and a record has commas and quoted tokens just like a
    # CSV row: read as a CSV, the first record becomes the "header" and the
    # object's *keys* get masked as though they were values, while the real
    # values are left claimed and unmasked. A CSV header row never starts
    # with { or [.
    if header.lstrip()[:1] in ("{", "["):
        return []
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


# PowerShell verbs, for telling a cmdlet name from a password. "$password =
# ConvertTo-SecureString ..." otherwise makes the masker redact the cmdlet and
# leave the credential standing next to it.
_PS_VERBS = (
    "get", "set", "new", "add", "remove", "convertto", "convertfrom", "invoke",
    "import", "export", "start", "stop", "select", "where", "foreach", "out",
    "write", "read", "test", "enter", "exit", "connect", "disconnect",
    "enable", "disable", "update", "install", "uninstall", "copy", "move",
    "rename", "restart", "join", "split", "format", "measure", "sort", "group",
    "send", "receive", "register", "unregister", "resolve", "search", "find",
    "clear", "push", "pop", "compare", "show", "wait", "restore", "save",
)


# "$cred", "$_", "@{Authorization=...}", "-Server": PowerShell syntax standing
# where a value would be, not the value itself.
_PS_NOT_A_VALUE = re.compile(r"^(?:\$[A-Za-z_]\w*|\$_|@[{(]|-[A-Za-z])")
# Same, minus the variable: a secret is the one thing we would rather mask
# twice than miss once, and 'ConvertTo-SecureString $ecret1' cannot be told
# from a variable by its shape. Masking a variable name costs nothing.
_PS_NOT_A_SECRET = re.compile(r"^(?:@[{(]|-[A-Za-z])")


def _luhn_ok(digits: str) -> bool:
    """The check digit every real card number carries. A 14-digit run that
    fails it is a timestamp, an order number or an epoch — not a card."""
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


# ---------------------------------------------------------------------------
# PowerShell.
#
# PowerShell is three shapes at once that no key=value pattern can follow:
#
#   * a parameter and its argument are separated by a space, not "=" or ":",
#     and the argument may be a comma-separated list — "-ComputerName A,B";
#   * results print as a space-aligned table under a row of dashes, where the
#     column header is the only clue to what the cells hold;
#   * a whole command can travel base64-encoded, where nothing is visible at
#     all until it is decoded.
#
# All three are collected here as explicit spans, claimed before the regex
# patterns run. This matters more than it looks: PowerShell is how a Windows
# investigation is actually conducted, so a transcript or a script-block log
# is one of the most common things to paste, and every device name, account
# and credential in it arrives in one of these three shapes.
# ---------------------------------------------------------------------------

# Parameters whose argument names a person or a machine. Deliberately not
# -Filter/-SearchBase/-Path: those carry their own patterns (DN, profile path)
# and would swallow half a query.
_PS_PARAM_LABELS = {
    "computername": "HOST", "cn": "HOST", "pscomputername": "HOST",
    "hostname": "HOST", "dnshostname": "HOST", "machinename": "HOST",
    "server": "HOST", "servername": "HOST", "serverinstance": "HOST",
    "node": "HOST", "vmname": "HOST", "clustername": "HOST",
    "smtpserver": "HOST", "connectionuri": "HOST",
    "resourcegroup": "RESOURCE", "resourcegroupname": "RESOURCE",
    "username": "USER", "user": "USER", "credential": "USER",
    "identity": "USER", "samaccountname": "USER", "mailbox": "USER",
    "userprincipalname": "USER", "accountname": "USER", "owner": "USER",
    "member": "USER", "sender": "USER", "manager": "USER",
    "givenname": "USER", "surname": "USER", "firstname": "USER",
    "lastname": "USER", "emailaddress": "USER",
    "vaultname": "RESOURCE", "keyvaultname": "RESOURCE",
    "storageaccountname": "RESOURCE", "workspacename": "RESOURCE",
    "subscriptionname": "RESOURCE",
    "streetaddress": "ADDRESS", "postalcode": "ADDRESS",
}
# PowerShell pluralises freely: -Members, -ComputerNames, -Identities.
for _sing, _lbl in list(_PS_PARAM_LABELS.items()):
    _PS_PARAM_LABELS.setdefault(_sing + "s", _lbl)
_PS_PARAM_LABELS["identities"] = "USER"
_PS_PARAM_LABELS["mailboxes"] = "USER"

# "-Name" and "-DisplayName" mean a person on one cmdlet and a Windows service
# on the next ("Get-Service -DisplayName 'Print Spooler'"), so they are read
# from the cmdlet on the same line rather than trusted on their own.
_PS_CONTEXT_PARAMS = ("name", "displayname")
_PS_NAME_CMDLET = re.compile(
    r"(?i)(?<![\w-])[A-Za-z]+-(?:AD|Az|Mg|Msol|Local)?"
    r"(User|ADUser|Mailbox|Person|Contact|Group|ADGroup"
    r"|VM|Computer|ADComputer)\b")
_PS_NAME_LABELS = {"user": "USER", "aduser": "USER", "mailbox": "USER",
                   "person": "USER", "contact": "USER", "group": "USER",
                   "adgroup": "USER", "vm": "HOST", "computer": "HOST",
                   "adcomputer": "HOST"}
_PS_PARAM = re.compile(r"(?i)(?<![\w-])--?([A-Za-z][A-Za-z\-]{1,23})[ \t]+"
                       r"(?=[\"']?[A-Za-z0-9])")
_PS_ITEM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\\@$\-]*")


def _ps_param_spans(text: str):
    """Spans for "-ComputerName WKS-01,WKS-02" style arguments, one span per
    list item so two machines never collapse into one alias."""
    out = []
    n = len(text)
    for m in _PS_PARAM.finditer(text):
        name = m.group(1).lower().replace("-", "")
        label = _PS_PARAM_LABELS.get(name)
        if not label and name in _PS_CONTEXT_PARAMS:
            line = text[text.rfind("\n", 0, m.start()) + 1:m.start()]
            cmdlet = _PS_NAME_CMDLET.search(line)
            label = _PS_NAME_LABELS.get(cmdlet.group(1).lower()) if cmdlet \
                else None
        if not label:
            continue
        i = m.end()
        while i < n:
            if text[i] in "\"'":
                # A quoted argument is one value even with a space in it:
                # -Identity "Domain Admins", -Name "Petra Vogel".
                close = text.find(text[i], i + 1)
                if close == -1:
                    break
                start, end, i = i + 1, close, close + 1
            else:
                item = _PS_ITEM.match(text, i)
                if not item:
                    break
                start, end, i = item.start(), item.end(), item.end()
            value = text[start:end]
            # An email or an IP handed to -Identity/-ComputerName keeps its
            # own, more precise label.
            if value and not (_FULL_IP.fullmatch(value)
                              or _FULL_EMAIL.fullmatch(value)):
                out.append((start, end, value, label))
            if i < n and text[i] == ",":       # the list continues
                i += 1
                while i < n and text[i] in " \t":
                    i += 1
                continue
            break
    return out


# Table column headers, checked before the CSV header rules.
_PS_COL_USER = ("samaccountname", "userprincipalname",
                "givenname", "surname", "fullname", "primaryownername",
                "principalname", "alias", "emailaddress", "mailbox",
                "accountname", "member", "manager", "identity")
# "DisplayName" and a bare "Name" are only readable from their neighbours.
_PS_COL_CONTEXT = ("displayname", "name")
_PS_COL_HOST = ("dnshostname", "pscomputername", "machinename", "servername",
                "computername", "hostname", "vmname", "nodename")
# A bare "Name" column is only readable from its neighbours: in Get-LocalUser
# it is a person, in Get-CimInstance Win32_ComputerSystem it is the machine,
# and in Get-Process it is a binary that must be left alone.
_PS_ACCOUNT_TABLE = ("enabled", "principalsource", "samaccountname",
                     "passwordrequired", "userprincipalname", "objectclass",
                     "lastlogon", "sid", "surname", "givenname")
_PS_MACHINE_TABLE = ("primaryownername", "manufacturer", "model",
                     "osarchitecture", "totalphysicalmemory", "dnshostname",
                     "domain")
# Tables about services, processes and files. Their Name and DisplayName
# columns are software, not people: masking "Print Spooler" out of
# Get-Service protects nobody and makes the output unreadable.
_PS_SOFTWARE_TABLE = ("status", "handles", "cpu", "processname", "starttype",
                      "servicetype", "lastwritetime", "length", "mode",
                      "version", "installdate", "publisher")
_PS_RULER = re.compile(r"^[ \t]*-{2,}(?:[ \t]+-{2,})+[ \t]*$")


def _ps_column_label(header: str, siblings) -> str:
    h = re.sub(r"[^a-z]", "", header.lower())
    if not h:
        return None
    if any(x in h for x in _PS_COL_USER):
        return "USER"
    if any(x in h for x in _PS_COL_HOST):
        return "HOST"
    if h in _PS_COL_CONTEXT:
        if any(x in sib for sib in siblings for x in _PS_SOFTWARE_TABLE):
            return None
        if any(x in sib for sib in siblings for x in _PS_ACCOUNT_TABLE):
            return "USER"
        if any(x in sib for sib in siblings for x in _PS_MACHINE_TABLE):
            return "HOST"
        return None
    return _csv_column_label(header)


def _ps_table_spans(text: str):
    """Spans for the sensitive columns of a Format-Table block: the row of
    dashes gives the column boundaries, the line above gives their names."""
    lines = text.split("\n")
    offsets, pos = [], 0
    for line in lines:
        offsets.append(pos)
        pos += len(line) + 1

    spans = []
    for idx, line in enumerate(lines):
        row = line.rstrip("\r")
        if idx == 0 or not _PS_RULER.match(row):
            continue
        header = lines[idx - 1].rstrip("\r")
        if not header.strip():
            continue
        # Column boundaries from the dashes; the last column runs to the end
        # of each row, since PowerShell truncates trailing whitespace.
        cols = [(mm.start(), mm.end()) for mm in re.finditer(r"-{2,}", row)]
        if len(cols) < 2:
            continue
        bounds = []
        for i, (cs, _ce) in enumerate(cols):
            end = cols[i + 1][0] - 1 if i + 1 < len(cols) else 10 ** 9
            bounds.append((cs, end))
        names = [header[cs:min(ce, len(header))].strip() for cs, ce in bounds]
        siblings = [re.sub(r"[^a-z]", "", nm.lower()) for nm in names]
        labels = [_ps_column_label(nm, siblings) for nm in names]
        if not any(labels):
            continue
        for row_idx in range(idx + 1, len(lines)):
            body = lines[row_idx].rstrip("\r")
            if not body.strip() or _PS_RULER.match(body):
                break
            for (cs, ce), label in zip(bounds, labels):
                if not label or cs >= len(body):
                    continue
                s, e = cs, min(ce, len(body))
                while s < e and body[s] in " \t":
                    s += 1
                while e > s and body[e - 1] in " \t":
                    e -= 1
                # A cell wider than its column overflows to the right instead
                # of wrapping, so the column boundary can fall inside a value:
                # take the whole token, or half a hostname is masked and the
                # other half is sent.
                while e < len(body) and body[e] not in " \t":
                    e += 1
                while s > 0 and body[s - 1] not in " \t":
                    s -= 1
                v = body[s:e]
                # Plain IPs / emails keep their own, more precise labels, and
                # a cell with no letter or digit ("{}", "...") names nothing.
                if not v or _FULL_IP.fullmatch(v) or _FULL_EMAIL.fullmatch(v):
                    continue
                if not re.search(r"[A-Za-z0-9]", v):
                    continue
                spans.append((offsets[row_idx] + s, offsets[row_idx] + e,
                              v, label))
    return spans


# powershell.exe -enc <base64>. The blob is UTF-16LE base64 and hides whatever
# it likes — an internal IP, a credential, a share path.
_PS_ENCODED = re.compile(
    r"(?i)(?<![\w-])-(?:e|ec|enc|encoded|encodedcommand)[ \t]+"
    r"([A-Za-z0-9+/]{40,}={0,2})")


def _decode_ps_command(blob: str) -> str:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except (ValueError, binascii.Error):
        return ""
    for encoding in ("utf-16-le", "utf-8"):
        try:
            out = raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
        # A wrong guess decodes to control characters, not a command.
        printable = sum(1 for c in out if c == "\n" or c == "\t" or c >= " ")
        if out and printable >= 0.9 * len(out):
            return out
    return ""


def _contains_sensitive(text: str) -> bool:
    """Would masking this text have masked anything? Used to decide whether an
    encoded command is hiding something."""
    for _category, label, pattern in _PATTERNS:
        # A hash or a UUID on its own identifies no one; see _KEEP_PATTERNS.
        if label in ("HASH", "UUID", "CC"):
            continue
        for m in pattern.finditer(text):
            s, e = m.span(m.lastindex) if m.lastindex else m.span()
            if _accept(label, text[s:e]):
                return True
    return False


def _ps_encoded_spans(text: str):
    """Spans for base64 -EncodedCommand blobs whose decoding holds something
    the masker would have masked in the clear.

    Masking the blob costs the reader the command, so it is only done when the
    command would have been masked anyway had it been typed out — the same
    answer either way, which is the property that makes this defensible. An
    encoded blob carrying nothing but an attacker's own script is left intact,
    because that is what the analyst is asking about."""
    spans = []
    for m in _PS_ENCODED.finditer(text):
        blob = m.group(1)
        if len(blob) > 1 << 18:            # 256 KB of base64; not a command
            continue
        decoded = _decode_ps_command(blob)
        if decoded and _contains_sensitive(decoded):
            spans.append((m.start(1), m.end(1), blob, "ENCODED"))
    return spans


def _ps_spans(text: str):
    return (_ps_param_spans(text) + _ps_table_spans(text)
            + _ps_encoded_spans(text))


# A value the masker has already decided is sensitive must not be left
# standing anywhere else in the same paste. A pattern can only anchor on one
# shape of a name — "Machine: WKS-01" in a transcript header — while the same
# name is echoed bare two lines down by `hostname`, where nothing marks it as
# anything. This is the difference between "the patterns matched" and "the
# value is gone", and only the second one is the promise the tool makes.
_PROPAGATE_MIN_LEN = 3
_PROPAGATE_MAX_MULTIWORD = 64
# A token, with the same boundaries a hostname or DOMAIN\user has. Scanning
# the text once and looking each token up beats matching every known value
# against the whole text, which on a large log is the difference between one
# pass and hundreds.
# Two readings, because a backslash both joins a token ("CORP\svc_backup" is
# one name) and separates one ("\\NAS-01\Finance" is a server and a share).
# Whichever reading matches a known value wins; the qualified one goes first
# so DOMAIN\user is not split into two placeholders.
_TOKEN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._\-@$]*")
_TOKEN_QUALIFIED = re.compile(
    r"[A-Za-z0-9_][A-Za-z0-9._\-@$]*(?:\\+[A-Za-z0-9._\-@$]+)+")
# The short form of an FQDN is the same machine: "WKS-01" is "WKS-01.corp
# .local". Only propagated when the label looks like a machine name rather
# than a word, so "mail" out of "mail.acme.com" is never chased through prose.
_MACHINE_ISH = re.compile(r"^(?=.*[\d-])[A-Za-z0-9][A-Za-z0-9\-]{3,}$")
# Words that are both a plausible NetBIOS domain and ordinary prose. The
# qualified "STORAGE\root_backup" is still masked in full; only the bare word
# is left alone, because masking every "storage" in a report is noise.
_GENERIC_DOMAIN_WORDS = {
    "storage", "finance", "security", "network", "backup", "system",
    "service", "services", "support", "office", "cloud", "group", "home",
    "main", "test", "users", "admin", "enterprise", "global", "internal",
    "external", "primary", "secondary", "production", "development",
    "marketing", "sales", "legal", "media", "data", "web", "mail",
}


def _propagate_spans(text: str, spans):
    """Spans for every other occurrence of a value already being masked."""
    known = {}
    for _s, _e, real, label in spans:
        if len(real) < _PROPAGATE_MIN_LEN:
            continue
        known.setdefault(real, label)
        # The domain half of DOMAIN\user is the customer's AD domain, and it
        # also stands alone in ACLs, group names and event fields where no
        # pattern can anchor on it.
        if label == "USER" and "\\" in real:
            prefix = real.split("\\", 1)[0]
            if len(prefix) >= _PROPAGATE_MIN_LEN \
                    and prefix.lower() not in _WINDOWS_BUILTIN_VALUES \
                    and prefix.lower() not in _GENERIC_DOMAIN_WORDS:
                known.setdefault(prefix, "DOMAIN")
        if label == "HOST" and "." in real:
            short = real.split(".", 1)[0]
            if _MACHINE_ISH.match(short):
                known.setdefault(short, "HOST")
    if not known:
        return []
    out = []
    # Single-token values: two passes over the text, a dict lookup per token.
    for token in (_TOKEN_QUALIFIED, _TOKEN):
        for m in token.finditer(text):
            tok, end = m.group(), m.end()
            label = known.get(tok)
            # A token class wide enough to hold "10.0.0.1" also swallows the
            # full stop that ends "...was raised in CORP." — try the token as
            # written first, then without its trailing punctuation.
            while label is None and tok and tok[-1] in ".-@$":
                tok, end = tok[:-1], end - 1
                label = known.get(tok)
            if label:
                out.append((m.start(), end, tok, label))
    # Values a token cannot hold (a distinguished name, "Anna Novak", an IPv6
    # address) are rarer; those get a literal scan each, and are capped so a
    # pathological log cannot turn this into a quadratic pass.
    multi = [v for v in known
             if not (_TOKEN.fullmatch(v) or _TOKEN_QUALIFIED.fullmatch(v))]
    for value in sorted(multi, key=len, reverse=True)[:_PROPAGATE_MAX_MULTIWORD]:
        for m in _exact_known_pattern(value).finditer(text):
            out.append((m.start(), m.end(), value, known[value]))
    return out


# When two patterns both claim a value, the name the analyst reads should be
# the specific one. "user=a.novak" and a bare "a.novak" in prose match the
# user pattern and the catch-all FQDN pattern respectively; calling the result
# [HOST_1] would tell the reader it is a machine.
_LABEL_RANK = {
    "CUSTOM": 0, "EMAIL": 1, "SID": 2, "DN": 3, "APIKEY": 4, "KEYID": 5,
    "ARN": 6, "SECRET": 7, "ACCTID": 8, "UUID": 9, "MAC": 10, "IP": 11,
    "IPV6": 12, "PHONE": 13, "ADDRESS": 14, "SERIAL": 15, "ENCODED": 16,
    "RESOURCE": 17, "USER": 18, "DOMAIN": 19, "ASSET": 20, "ORG": 21,
    "GROUP": 22, "SUBJECT": 23, "HOST": 24, "CC": 25, "HASH": 26,
}


def _accept(label: str, value: str) -> bool:
    """Reject false positives before we commit to masking a match."""
    v = value.strip()
    if not v:
        return False
    # A PowerShell variable, a splatted hashtable or the following parameter
    # is never itself the value: "-Credential $cred", "-Headers @{...}",
    # "-Identity -Server". Only these exact shapes — a real password is
    # allowed to start with "$", so "$ecret1" must still be masked.
    if (_PS_NOT_A_SECRET if label == "SECRET" else _PS_NOT_A_VALUE).match(v):
        return False
    if label == "SECRET" and "-" in v \
            and v.lstrip("([{").split("-", 1)[0].lower() in _PS_VERBS:
        return False
    if label in ("USER", "DOMAIN", "HOST", "ASSET", "ORG", "GROUP",
                 "SUBJECT") and v.lower() in _WINDOWS_BUILTIN_VALUES:
        return False
    # An app name that names the vendor's product rather than the customer's
    # own resource is the point of the alert -- see _SAAS_APP_ALLOWLIST.
    if label in ("ASSET", "ORG") and v.lower() in _SAAS_APP_ALLOWLIST:
        return False
    # SaaS audit logs use "0" / "1" / "-1" for absent org and group ids;
    # a group or topic of one or two characters names nothing.
    if label in ("ASSET", "ORG", "GROUP", "SUBJECT") and len(v) < 3:
        return False
    if label in ("USER", "DOMAIN", "HOST") and v[0] == "\\":
        return False
    # A short well-known SID (S-1-5-18 SYSTEM, S-1-5-19/20 the local services)
    # names a built-in account. The SID pattern deliberately leaves those
    # readable -- a "UserID='S-1-5-18'" key=value match must not undo it.
    if label in ("USER", "DOMAIN", "HOST") and _SHORT_SID.fullmatch(v):
        return False
    # NT AUTHORITY\SYSTEM, NT SERVICE\TrustedInstaller, BUILTIN\Administrators…
    if label == "USER" and "\\" in v:
        prefix, account = v.lower().split("\\", 1)
        if prefix in _BUILTIN_DOMAIN_PREFIXES or prefix in _DOMAIN_ALLOWLIST:
            return False
        # "CORP\Domain Admins" names a built-in group, not a person.
        if account.strip("\\") in _WINDOWS_BUILTIN_VALUES:
            return False
        # Two halves of one Windows path rather than DOMAIN\account: Sysmon
        # Image / CommandLine fields are full of them, and a space inside the
        # path is what let the match start in the middle of it.
        if prefix.rsplit(" ", 1)[-1] in _PATH_WORDS \
                or account.split("\\", 1)[0] in _PATH_WORDS \
                or _PATH_FILE_EXT.search(account):
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
        if not _luhn_ok(digits):
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
         base_counters: Dict[str, int] = None,
         builtin_patches: Dict[str, str] = None,
         keep_terms: List[str] = None) -> Tuple[str, Dict[str, str]]:
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
    `keep_terms` are exact strings that must never be masked, whatever any
    pattern says. They claim their span before anything else runs -- including
    before the conversation's own known values, so a value wrongly learned
    earlier stops being re-masked the moment it is added here.
    `builtin_patches` maps a built-in pattern id to a replacement regex for
    this call only. The regex workbench uses it to answer "would this edit
    have caught the value?" at the pattern's real priority, without saving an
    override, and without a global swap that a concurrent request could see.
    """
    enabled_set = set(enabled)

    patterns = list(_PATTERNS)
    for pattern_id, replacement in (builtin_patches or {}).items():
        for i, (pid, _src, _note) in enumerate(_PATTERN_META):
            if pid != pattern_id:
                continue
            try:
                cat, label, _rx = patterns[i]
                patterns[i] = (cat, label, re.compile(replacement))
            except re.error:
                pass                # a broken candidate leaves the default
            break
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

    # The analyst's own never-mask list, ahead of everything: this is the
    # override for "you masked something that identifies nobody", and it has
    # to beat the conversation mapping as well as the patterns.
    for term in sorted({t.strip() for t in (keep_terms or []) if t.strip()},
                       key=len, reverse=True):
        for m in re.finditer(_exact_known_pattern(term).pattern, text,
                             re.IGNORECASE):
            if not overlaps(m.start(), m.end()):
                take(m.start(), m.end())

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

    # PowerShell parameter arguments, Format-Table columns and encoded
    # commands — the shapes no regex can follow (see _ps_spans).
    for s, e, real, label in _ps_spans(text):
        if not _accept(label, real) or overlaps(s, e):
            continue
        take(s, e)
        spans.append((s, e, real, label))

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

    # Second pass: the same real values, wherever else they appear.
    for s, e, real, label in _propagate_spans(text, spans):
        if overlaps(s, e):
            continue
        take(s, e)
        spans.append((s, e, real, label))

    # One label per value, by specificity rather than by whichever occurrence
    # happens to be numbered first (see _LABEL_RANK).
    best: Dict[str, str] = {}
    for _s, _e, real, label in spans:
        current = best.get(real)
        if current is None or _LABEL_RANK.get(label, 99) \
                < _LABEL_RANK.get(current, 99):
            best[real] = label
    spans = [(s, e, real, best[real]) for s, e, real, _lbl in spans]

    # Assign stable placeholders. Same real value -> same placeholder.
    # Seed from the conversation's existing mapping so placeholders stay
    # consistent across turns and numbering continues where it left off.
    mapping: Dict[str, str] = {}              # placeholder -> real
    reverse: Dict[Tuple[str, str], str] = {}  # (label, real) -> placeholder
    by_value: Dict[str, str] = {}             # real -> placeholder
    counters: Dict[str, int] = {}
    for ph, real in (base_mapping or {}).items():
        mapping[ph] = real
        m = re.fullmatch(r"\[([A-Z0-9]+)_(\d+)\]", ph)
        if m:
            reverse[(m.group(1), real)] = ph
            by_value.setdefault(real, ph)
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
            # The same real value must not end up behind two aliases because
            # two patterns disagreed about what to call it: an address caught
            # once as [EMAIL_1] and once as [USER_2] reads as two people.
            placeholder = by_value.get(real)
        if placeholder is None:
            counters[label] = counters.get(label, 0) + 1
            placeholder = f"[{label}_{counters[label]}]"
            mapping[placeholder] = real
        reverse[key] = placeholder
        by_value.setdefault(real, placeholder)
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
