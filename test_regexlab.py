"""Checks for the local regex workbench. Run: python test_regexlab.py

The workbench exists so that a log too sensitive to send to an AI provider is
also never pasted into an online regex tester. Everything below therefore
asserts on behaviour that must hold with no network at all.
"""

import os
import tempfile

from log_masker import masker, regexlab

try:
    from cryptography.fernet import Fernet
    from log_masker import vault
    vault.configure(os.path.join(tempfile.mkdtemp(prefix="regexlab_test_"),
                                 "vault.enc"),
                    Fernet.generate_key().decode())
except ImportError:
    pass

ALL = ["identities", "network", "secrets"]


def check(name, cond):
    print(("PASS" if cond else "FAIL") + " - " + name)
    assert cond, name


def test_diagnosis_tells_the_four_apart():
    """Four different reasons a value survives, four different fixes. Getting
    this wrong sends someone off to edit a regex that was never the problem."""
    # 1. Nothing matched.
    r = regexlab.diagnose("audit: assetLabel=WKS-FIN-042 action=block\n",
                          "WKS-FIN-042")
    check("no pattern matched -> no_match", r["verdict"] == "no_match")

    # 2. A pattern matched and _accept threw the value out.
    r = regexlab.diagnose("host=localhost port=443\n", "localhost")
    check("allow-listed value -> rejected", r["verdict"] == "rejected")
    check("and it says which rule",
          "allow-list" in (r["hits"][0]["reason"] or "")
          or "built-in" in (r["hits"][0]["reason"] or ""))

    # 3. A protected span claimed it.
    r = regexlab.diagnose('{"sha256":"a3f1b2c4d5e6f7089a1b2c3d4e5f60718293a4b5"'
                          '}\n', "a3f1b2c4d5e6f7089a1b2c3d4e5f60718293a4b5")
    check("file hash -> protected", r["verdict"] == "protected")

    # 4. It was masked all along.
    r = regexlab.diagnose("user=jsmith from 10.4.2.19\n", "jsmith")
    check("already handled -> already_masked",
          r["verdict"] == "already_masked")


def test_no_suggestions_when_a_regex_is_not_the_fix():
    """Three of the four verdicts are fixed somewhere other than a regex, and
    a confident suggestion there is worse than none: every candidate 'verifies'
    trivially, because the value was already gone."""
    for sample, value in (("user=jsmith\n", "jsmith"),
                          ('{"sha1":"da39a3ee5e6b4b0d3255bfef95601890afd80709"}',
                           "da39a3ee5e6b4b0d3255bfef95601890afd80709")):
        r = regexlab.suggest(sample, value)
        check(f"no suggestions for {r['verdict']}", r["suggestions"] == [])


def test_widens_the_built_in_that_should_have_caught_it():
    sample = "  Requesting Workstation:   WS-FIN-07\n"
    r = regexlab.suggest(sample, "WS-FIN-07")
    check("an unknown field is a no_match", r["verdict"] == "no_match")
    top = r["suggestions"][0]
    check("the first suggestion widens a built-in",
          top["kind"] == "extend_builtin")
    # An indented field label belongs to the Windows event pattern, not to the
    # generic host= one, even though both end in a colon.
    check("and it is the right built-in", top["id"] == "winevent-host")
    check("the new key is in the regex", "Workstation" in top["regex"])
    check("the old keys are still there",
          "Caller Computer Name" in top["regex"])
    # The proposal is verified, not guessed: applied at the built-in's own
    # priority, the value is gone.
    masked, _ = masker.mask(sample, ALL,
                            builtin_patches={top["id"]: top["regex"]})
    check("applying it actually masks the value", "WS-FIN-07" not in masked)


def test_suggestions_are_verified_at_the_real_priority():
    """A candidate that only works because it was tried at the top of the
    list would fail the moment it was saved."""
    sample = "Invoke-Thing -TargetBox SRV-DB-04 -Force\n"
    r = regexlab.suggest(sample, "SRV-DB-04")
    for s in r["suggestions"]:
        if s["kind"] == "extend_builtin":
            masked, _ = masker.mask(sample, ALL,
                                    builtin_patches={s["id"]: s["regex"]})
            check(f"{s['id']} verified in place", "SRV-DB-04" not in masked)
        elif s["kind"] in ("new_pattern", "literal"):
            masked, _ = masker.mask(sample, ALL, custom_patterns=[
                {"label": s["label"], "regex": s["regex"]}])
            check(f"{s['kind']} verified as saved",
                  "SRV-DB-04" not in masked)


def test_a_candidate_must_match_where_the_value_sits():
    """Without a positional check a JSON key can be 'verified' into an XML
    pattern, because the value was already gone for an unrelated reason."""
    sample = '<Event><Data Name="RequesterName">thall</Data></Event>\n'
    r = regexlab.suggest(sample, "thall")
    ids = [s.get("id") for s in r["suggestions"] if s["kind"] == "extend_builtin"]
    check("the XML pattern is proposed", "winxml-user" in ids)
    check("a key=value pattern is not", "user-kv" not in ids)


def test_patches_do_not_leak_into_other_calls():
    """builtin_patches is per-call. If it were a global swap, a concurrent
    analysis would mask with a half-finished candidate."""
    sample = "  Requesting Workstation:   WS-FIN-07\n"
    patched, _ = masker.mask(sample, ALL, builtin_patches={
        "winevent-host": r"(?im)^[ \t]*Requesting Workstation[ \t]*:[ \t]*"
                         r"([^\r\n]+?)[ \t]*$"})
    plain, _ = masker.mask(sample, ALL)
    check("the patch applies to its own call", "WS-FIN-07" not in patched)
    check("and to no other", "WS-FIN-07" in plain)
    # A candidate that does not compile must not take the default down with it.
    broken, _ = masker.mask(sample, ALL,
                            builtin_patches={"winevent-host": "([unclosed"})
    check("a broken candidate falls back to the default",
          broken == plain)


def test_try_regex_reports_matches_and_rejections():
    sample = "host=WS-01 host=localhost\n"
    out = regexlab.try_regex(sample, r"host=([A-Za-z0-9\-]+)", "HOST")
    check("the candidate compiles", out["ok"])
    check("both occurrences are reported", len(out["matches"]) == 2)
    accepted = [m for m in out["matches"] if m["accepted"]]
    check("one is accepted", len(accepted) == 1)
    rejected = [m for m in out["matches"] if not m["accepted"]][0]
    check("and the other says why it is not",
          rejected["text"] == "localhost" and rejected["reason"])
    check("a dangerous regex is refused",
          not regexlab.try_regex("aaaa", r"(a+)+$", "HOST")["ok"])


def test_every_rejection_has_a_reason():
    """_why_rejected mirrors _accept. If a rule is added there and not here,
    the workbench says 'an _accept() rule rejected it' and helps nobody."""
    samples = [
        ("HOST", "localhost"), ("HOST", "example.com"), ("HOST", "info"),
        ("HOST", "report.pdf"), ("HOST", "microsoft.graph.deviceEvidence"),
        ("USER", "SYSTEM"), ("USER", "NT AUTHORITY\\SYSTEM"),
        ("USER", "CORP\\Domain Admins"), ("USER", "1000"),
        ("USER", "\\s"), ("USER", "$cred"),
        ("SECRET", "ConvertTo-SecureString"), ("SECRET", "@{a=1}"),
        ("SECRET", "/home/jsmith"),
        ("IP", "127.0.0.1"), ("IPV6", "::1"),
        ("CC", "20260902141233"), ("CC", "1234"),
    ]
    generic = 0
    for label, value in samples:
        if masker._accept(label, value):
            check(f"{label} {value!r} is rejected by _accept", False)
        reason = regexlab._why_rejected(label, value)
        check(f"{label} {value!r} has a reason", bool(reason))
        if reason == "an _accept() rule rejected it":
            generic += 1
    check("no rejection falls through to the generic reason", generic == 0)


def test_sample_and_value_must_line_up():
    r = regexlab.suggest("nothing here\n", "WS-01")
    check("a value not in the sample is refused", not r["ok"])
    check("and says so", "does not appear" in r["error"])
    check("an empty value is refused", not regexlab.suggest("x", "")["ok"])


if __name__ == "__main__":
    test_diagnosis_tells_the_four_apart()
    test_no_suggestions_when_a_regex_is_not_the_fix()
    test_widens_the_built_in_that_should_have_caught_it()
    test_suggestions_are_verified_at_the_real_priority()
    test_a_candidate_must_match_where_the_value_sits()
    test_patches_do_not_leak_into_other_calls()
    test_try_regex_reports_matches_and_rejections()
    test_every_rejection_has_a_reason()
    test_sample_and_value_must_line_up()
    print("\nAll regex workbench tests passed.")
