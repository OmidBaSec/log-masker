# Security policy

Log Masker exists to keep sensitive data out of third-party AI providers, so a
security bug here can have real consequences for the people whose logs are being
analysed. Reports are welcome and taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's [private vulnerability reporting][ghsa] on this repository
(Security → Report a vulnerability). If that is unavailable to you, open a
regular issue containing only "security report, please provide a contact
address" — with no details — and a maintainer will follow up.

[ghsa]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

What to expect:

| | |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment | within 10 working days |
| Fix or mitigation plan | agreed with you before disclosure |
| Credit | offered by default; tell us if you would rather stay anonymous |

This is a volunteer-maintained project with no bug bounty.

## What is in scope

Anything that could expose data the tool is supposed to protect, or that lets
someone else drive an analyst's instance:

* **Masking bypasses** — an input where a sensitive value survives into the
  masked output. A failing sample log is the ideal report; it usually becomes a
  regression test.
* **Leak-guard bypasses** — masked output that the pre-send check should have
  flagged and did not.
* **Unmasking or vault exposure** — any path that reveals real values to a
  caller that should not see them, or that reads the entity vault off disk.
* **Request-guard bypasses** — CSRF, DNS rebinding, or any way for a web page
  the analyst visits to reach the local API. See `guard.py` for the model.
* **Secret handling** — API keys or the vault key ending up somewhere they
  should not (logs, the audit trail, error messages, world-readable files).
* **Remote code execution, path traversal, resource exhaustion** in the local
  server, including via uploaded spreadsheets.

## What is out of scope

* **Incomplete masking of a category we do not claim to detect.** Masking is
  pattern-based and best-effort; see "What this tool does and does not
  guarantee" in the README. A *new* pattern suggestion is a feature request, not
  a vulnerability — though a value that the documented categories *should* have
  caught is very much in scope.
* **Attacks that require code already running as the analyst.** Local code can
  read the data directory directly; the boundary we defend is the browser and
  the network, not the user's own account.
* **Binding the server to a public interface on purpose.** The app refuses this
  unless `LOGMASKER_ALLOW_REMOTE=1` is set, which is documented as "you are now
  responsible for authentication".
* Findings from automated scanners with no demonstrated impact.
* Vulnerabilities in an AI provider's own service.

## Supported versions

The latest release on `main` is supported. There are no long-term support
branches yet.

## Threat model in one paragraph

Log Masker runs on the analyst's machine, listens only on loopback, and has no
authentication — anything that can reach the port is treated as the analyst.
Raw logs never leave the machine; masked text goes to whichever AI provider the
analyst configured, and the mask→real mapping stays in the local process and the
encrypted entity vault. API keys live in the OS keychain, or in a Fernet-encrypted
file where no keychain exists. The audit log records what was sent, in masked
form. The adversaries we design against are: a web page the analyst visits, a
malicious log file, and an AI provider that sees everything it is sent.
