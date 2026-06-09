"""Quick checks for the masking engine. Run: python test_masker.py"""

import masker

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


if __name__ == "__main__":
    test_roundtrip()
    test_ipv6_vs_timestamp()
    test_bare_hostname_param()
    test_custom_terms()
    test_stable_placeholders()
    test_category_toggle()
    test_no_false_positive_filenames()
    print("\nAll masker tests passed.")
