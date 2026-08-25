# Changelog

All notable changes to Log Masker. Format follows [Keep a Changelog][kac];
versions follow [Semantic Versioning][semver].

[kac]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

## [0.9.0] — 2026-08-25

First release prepared for public use. Everything before this was developed in
private, so this entry describes the state rather than the diff.

### Added
- **Runs on macOS, Windows and Linux.** Per-OS data directory (`paths.py`),
  a secret store that falls back to an encrypted file where there is no OS
  keychain (`keystore.py`), and a pure-Python launcher (`log_masker/cli.py`)
  with `run.sh`, `run.ps1` and `run.bat` wrappers.
- **Installable**: `pip install .` provides a `log-masker` console script; the
  UI ships as package data.
- **Container image**: `Dockerfile` (multi-stage, non-root, read-only rootfs)
  and `docker-compose.yml` with an optional Ollama profile.
- **Request guard** (`guard.py`) against CSRF and DNS rebinding, plus a refusal
  to bind a non-loopback interface without an explicit opt-in.
- **Log file encoding detection** — UTF-16 Windows exports were previously
  rejected as binary files.
- **Credit and spend view**: per-provider month-to-date and all-time cost
  priced from the audit log, and a running cost per conversation.
- **Light / dark / follow-the-OS theme.**
- `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `sample_logs/`, and a CI matrix across three operating
  systems and two Python versions.

### Changed
- **Requires Python 3.11+.** On 3.9 the patched Starlette and python-multipart
  cannot be installed at all; `pip-audit` reported 15 known vulnerabilities
  there and reports none now.
- Audit and vault timestamps are ISO-8601 with a UTC offset.
- Masking categories are no longer selectable in the UI; every analysis masks
  identities, network and secrets.

### Fixed
- **Masking was quadratic twice over** — an O(n²) overlap scan and a whole-text
  copy per replacement. A 0.5 MB log took minutes and now takes ~0.3 s, making
  the documented 10 MB limit usable. Output is byte-identical to before.
- Chunked request bodies bypassed the request size limit.
- An origin check accepted any loopback address, so another local app could
  drive this one.
- `UVICORN_HOST` bypassed the non-loopback bind refusal entirely.
- Spreadsheet import had no zip-bomb, cell-count or parse-time limits.
- `./run.sh` with no arguments crashed under `set -u` on macOS's bash 3.2.
- A misconfigured data directory or master key failed with a misleading error.

### Security
- The threat model, and what the tool does *not* guarantee, are documented in
  the README and `SECURITY.md`. Masking is best-effort and pattern-based; the
  audit log evidences what was sent rather than proving nothing leaked.

[Unreleased]: https://github.com/OmidBaSec/log-masker/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/OmidBaSec/log-masker/releases/tag/v0.9.0
