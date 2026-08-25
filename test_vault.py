"""Checks for the persistent entity vault. Run: python test_vault.py

Uses a throwaway vault file with a fixed key — the real vault and the OS
keychain are never touched.
"""

import os
import tempfile

from cryptography.fernet import Fernet

from log_masker import masker
from log_masker import vault

ALL = ["identities", "network", "secrets"]
KEY = Fernet.generate_key().decode()
_TMP = tempfile.mkdtemp(prefix="vault_test_")


def check(name, cond):
    print(("PASS" if cond else "FAIL") + " - " + name)
    assert cond, name


def fresh(name):
    """Point the vault at a new empty file (resets all caches)."""
    path = os.path.join(_TMP, name + ".enc")
    vault.configure(path, KEY)
    return path


def vmask(text):
    """Mask the way app.py does with the vault on: seed mapping + counter
    floors, then trim to the placeholders actually used in this text."""
    masked, mapping = masker.mask(text, ALL, base_mapping=vault.mapping(),
                                  base_counters=vault.counters())
    used = {ph: real for ph, real in mapping.items() if ph in masked}
    return masked, used


def test_record_and_mapping():
    fresh("record")
    check("empty vault has empty mapping", vault.mapping() == {})
    n = vault.record("inc1", {"[USER_1]": "jsmith", "[IP_1]": "10.4.2.19"})
    check("two new entities recorded", n == 2)
    check("mapping returns entities",
          vault.mapping() == {"[USER_1]": "jsmith", "[IP_1]": "10.4.2.19"})
    # Re-recording the same entity in another incident is not "new".
    n = vault.record("inc2", {"[USER_1]": "jsmith"})
    check("known entity is not counted as new", n == 0)
    ents = {e["placeholder"]: e for e in vault.entities()}
    check("entity carries both incidents",
          [i["id"] for i in ents["[USER_1]"]["incidents"]] == ["inc1", "inc2"])
    check("stats count entities and incidents",
          vault.stats()["entities"] == 2 and vault.stats()["incidents"] == 2)
    # Malformed placeholders are ignored.
    n = vault.record("inc3", {"not-a-placeholder": "x", "[BAD]": "y"})
    check("malformed placeholders ignored", n == 0)


def test_cross_incident_stability():
    fresh("stability")
    masked1, used1 = vmask("user=jsmith failed login from 10.4.2.19")
    vault.record("inc1", used1)
    ph_user = [p for p, v in used1.items() if v == "jsmith"][0]

    # A later, unrelated log mentioning the same user: same placeholder,
    # and the new IP continues the numbering instead of restarting at _1.
    masked2, used2 = vmask("user=jsmith connected to 10.99.0.7")
    check("same value keeps its placeholder across incidents",
          ph_user in masked2)
    check("real value absent from second mask", "jsmith" not in masked2)
    new_ip_ph = [p for p, v in used2.items() if v == "10.99.0.7"][0]
    check("numbering continues globally", new_ip_ph == "[IP_2]")


def test_persistence():
    path = fresh("persist")
    _, used = vmask("user=jdoe from 192.168.7.7")
    vault.record("incA", used)
    before = vault.mapping()
    check("vault file exists and is not plaintext",
          os.path.exists(path) and b"jdoe" not in open(path, "rb").read())
    # Simulate a restart: reconfigure the same file drops the memory cache.
    vault.configure(path, KEY)
    check("entities survive a restart", vault.mapping() == before)


def test_context_lines():
    fresh("context")
    _, used1 = vmask("user=jsmith failed login from 10.4.2.19")
    vault.record("inc1", used1)
    vault.set_verdict("inc1", "true_positive", "high")
    _, used2 = vmask("user=jsmith locked out on 10.4.2.19")
    vault.record("inc2", used2)
    vault.set_verdict("inc2", "false_positive", "low")

    ph_user = [p for p, v in used1.items() if v == "jsmith"][0]
    lines = vault.context_lines([ph_user, "[HOST_99]"])
    check("history only for known placeholders", len(lines) == 1)
    check("line names the placeholder", ph_user in lines[0])
    check("line counts prior analyses", "2 prior analyses" in lines[0])
    check("line aggregates verdicts",
          "true_positive ×1" in lines[0] and "false_positive ×1" in lines[0])
    # The whole point: no real value may ever appear in prompt context.
    all_reals = list(used1.values()) + list(used2.values())
    check("no real value leaks into context lines",
          all(real not in line for real in all_reals for line in lines))
    check("unknown placeholders yield no context",
          vault.context_lines(["[HOST_99]"]) == [])


def test_forget_retires_number():
    fresh("forget")
    _, used = vmask("traffic from 10.0.0.1 to 10.0.0.2")
    vault.record("inc1", used)
    check("two IPs vaulted", vault.stats()["entities"] == 2)

    check("forget removes the entity", vault.forget("[IP_2]"))
    check("forget of unknown placeholder is refused",
          not vault.forget("[IP_2]"))
    check("mapping no longer has the entity", "[IP_2]" not in vault.mapping())

    # A brand-new IP must NOT inherit the retired [IP_2] alias.
    masked, used2 = vmask("probe from 172.16.9.9")
    ph_new = [p for p, v in used2.items() if v == "172.16.9.9"][0]
    check("retired number is never reused", ph_new == "[IP_3]")


def test_clear():
    fresh("clear")
    _, used = vmask("user=jsmith from 10.4.2.19")
    vault.record("inc1", used)
    vault.clear()
    check("clear empties the vault",
          vault.mapping() == {} and vault.stats()["incidents"] == 0)
    # After a clear, numbering starts over by design.
    _, used2 = vmask("ping from 10.9.9.9")
    check("numbering restarts after clear", "[IP_1]" in used2)


def test_unreadable_file_is_set_aside():
    path = fresh("garbage")
    with open(path, "wb") as f:
        f.write(b"this is not a fernet token")
    vault.configure(path, KEY)          # reset cache so it re-reads the file
    check("unreadable vault starts empty", vault.mapping() == {})
    check("a warning is surfaced", "could not be decrypted" in vault.status_warning())
    check("the unreadable file was set aside, not deleted",
          any(n.startswith("garbage.enc.unreadable-") for n in os.listdir(_TMP)))
    # And the vault is usable again.
    vault.record("inc1", {"[IP_1]": "10.1.1.1"})
    check("vault usable after reset", vault.mapping() == {"[IP_1]": "10.1.1.1"})


def test_app_analyze_integration():
    """End-to-end through app.analyze(): the second incident that mentions a
    known entity reuses its placeholder and gets cross-incident context in
    the system prompt — statistics only, never the real value."""
    import json
    from log_masker import app as appmod

    fresh("app")
    try:
        with open(appmod.CONFIG_FILE, encoding="utf-8") as f:
            config_backup = f.read()
    except FileNotFoundError:
        config_backup = None
    captured = {}

    def fake_call(provider, api_key, model, system, messages, cfg, **k):
        captured["system"] = system
        return "Looks suspicious."

    real_call, real_key = appmod.providers.call, appmod.get_api_key
    conv_ids = []
    try:
        appmod.providers.call = fake_call
        appmod.get_api_key = lambda provider: "stub-key"

        res1 = appmod.analyze(appmod.AnalyzeRequest(
            logs="failed login user=jsmith from 10.4.2.19", structured=False))
        conv_ids.append(res1["conversation_id"])
        check("first sight: no recurring entities",
              res1["vault"]["recurring"] == 0)
        check("first sight: no context block",
              "Cross-incident context" not in captured["system"])
        check("response mapping is trimmed to this log",
              set(res1["mapping"].values()) == {"jsmith", "10.4.2.19"})

        res2 = appmod.analyze(appmod.AnalyzeRequest(
            logs="user=jsmith escalated privileges on 10.4.2.19",
            structured=False))
        conv_ids.append(res2["conversation_id"])
        check("recurring entities reported", res2["vault"]["recurring"] == 2)
        check("context block attached to the prompt",
              "Cross-incident context" in captured["system"])
        check("context carries no real values",
              "jsmith" not in captured["system"]
              and "10.4.2.19" not in captured["system"])
        ph1 = {v: p for p, v in res1["mapping"].items()}
        ph2 = {v: p for p, v in res2["mapping"].items()}
        check("placeholders stable across the two analyses", ph1 == ph2)

        res3 = appmod.analyze(appmod.AnalyzeRequest(
            logs="user=jsmith logged out", structured=False,
            vault_context=False))
        conv_ids.append(res3["conversation_id"])
        check("vault_context=False suppresses the block",
              "Cross-incident context" not in captured["system"])
    finally:
        appmod.providers.call = real_call
        appmod.get_api_key = real_key
        for cid in conv_ids:
            appmod.CONVERSATIONS.pop(cid, None)
        if config_backup is None:
            try:
                os.remove(appmod.CONFIG_FILE)
            except FileNotFoundError:
                pass
        else:
            with open(appmod.CONFIG_FILE, "w", encoding="utf-8") as f:
                f.write(config_backup)


if __name__ == "__main__":
    test_record_and_mapping()
    test_cross_incident_stability()
    test_persistence()
    test_context_lines()
    test_forget_retires_number()
    test_clear()
    test_unreadable_file_is_set_aside()
    test_app_analyze_integration()
    print("\nAll vault tests passed.")
