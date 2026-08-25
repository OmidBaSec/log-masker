# Contributing

Thanks for looking. This is a security tool that people point at real customer
logs, so the bar for changes to the masking path is deliberately high — but the
project is small, dependency-light and easy to run.

## Getting set up

Python **3.11 or newer** (3.9 and 3.10 cannot install the patched versions of
some dependencies).

```bash
git clone https://github.com/OmidBaSec/log-masker.git
cd log-masker
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.lock
python cli.py start --open
```

No API key is needed to work on masking: paste a log and use **Preview
masking**, which never contacts a provider.

## Running the tests

Plain scripts, no test runner, no plugins:

```bash
python test_masker.py      # masking, leak guard, prompt assembly
python test_vault.py       # persistent entity vault
python test_providers.py   # provider abstraction + usage capture
python test_credits.py     # pricing and spend accounting
python test_security.py    # request guard, data paths, secret storage
python test_cli.py         # launcher: start/stop/status on this OS
node   test_frontend.js    # log-file encoding detection
```

All of them must pass on macOS, Windows and Linux — that is what the CI matrix
checks. If you cannot run all three, open the PR anyway and let CI tell you.

## What a good change looks like

**Every masking change needs a test.** The suite is mostly masking cases for a
reason: a regression there leaks customer data. Add the failing sample first,
then fix it.

**Prefer a failing sample log over a description.** For a masking gap, a
minimal (synthetic!) log line that should be masked and is not is worth more
than any amount of prose. Never attach a real log.

**Explain the "why" in comments, not the "what".** The existing code comments
say why a decision was made — read a few before writing yours.

**Keep the dependency list short.** Every dependency is supply-chain risk in a
tool people install because they distrust the cloud. `paths.py` and `cli.py`
both deliberately avoid a popular library in favour of ~15 lines of standard
library. New dependencies need a good argument.

**Do not add telemetry, analytics, crash reporting or auto-update.** The
premise of the tool is that nothing leaves the machine unasked.

## Adding a masking pattern

Built-in patterns live in `masker.py`. A useful pattern is:

* **Anchored.** `\b`-bounded, or keyed off a field name (`user=`, `token=`).
  Unanchored patterns produce false positives that mask half a log.
* **Tested both ways** — a case it must catch, and a near-miss it must leave
  alone. A pattern that masks a timestamp as an IPv6 address is worse than no
  pattern.
* **Categorised** into identities / network / secrets, with a label that reads
  well as a placeholder (`[HOST_1]`, not `[REGEXMATCH_1]`).

For patterns specific to your environment, prefer the in-app **Masking Rules**
view — the built-ins should stay generally useful.

## Adding a provider

`providers.py` has one function per provider plus a registry entry. A new
provider needs: the call, usage/token capture (so the credit view stays honest),
a model list if the API exposes one, and an entry in `PROVIDERS` with its key
label and billing URL. If it speaks the OpenAI chat-completions dialect, say so
in the PR — a generic OpenAI-compatible adapter is on the roadmap and yours may
be one config entry rather than a new module.

## Commit and PR style

* Present tense, imperative subject: "Refuse chunked request bodies".
* Say **why** in the body. Defects found and fixed are worth spelling out.
* One logical change per PR where you can manage it.
* CI must be green: six Python suites, the frontend tests, `pip-audit`, and a
  secret scan.

## Security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## Licence

Contributions are accepted under the [Apache License 2.0](LICENSE), the same
licence as the project.
