"""
Where Log Masker keeps its data — on macOS, Windows and Linux alike.

Resolution order, first match wins:

  1. ``LOGMASKER_DATA_DIR``     — explicit; what Docker and portable installs set.
  2. The directory holding this code, **if it already contains app data** —
     so an existing side-by-side install keeps working exactly where it is,
     and `python cli.py` from a checkout stays self-contained.
  3. The per-user application directory for this OS:
       macOS    ~/Library/Application Support/LogMasker
       Windows  %APPDATA%\\LogMasker
       Linux    $XDG_DATA_HOME/logmasker  (default ~/.local/share/logmasker)

Nothing is ever moved between those locations: rule 2 means an upgrade never
relocates a vault or an audit trail behind the analyst's back, while a fresh
install (pip, Docker, a packaged binary — anywhere the code directory is
read-only or shared) lands in the right per-user place from the start.
"""

import os
import sys
from typing import Optional

APP_NAME = "LogMasker"
ENV_VAR = "LOGMASKER_DATA_DIR"

CODE_DIR = os.path.dirname(os.path.abspath(__file__))

# Files that mark a directory as holding a Log Masker installation's data.
# (The audit log and the vault are the two that must never be orphaned.)
DATA_FILES = (
    "ai_requests.jsonl",
    "entity_vault.enc",
    "custom_store.json",
    "app_config.json",
    "templates_store.json",
    "builtin_overrides.json",
    "custom_patterns.json",
    "pricing.json",
    "m365_token_cache.json",
)

_RESOLVED: Optional[str] = None


def _user_data_dir() -> str:
    """The conventional per-user data directory for this platform."""
    if sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~"), "Library",
                            "Application Support", APP_NAME)
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Roaming")
        return os.path.join(base, APP_NAME)
    # Linux/BSD: XDG Base Directory spec.
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, APP_NAME.lower())


def _has_data(directory: str) -> bool:
    return any(os.path.exists(os.path.join(directory, f)) for f in DATA_FILES)


def data_dir() -> str:
    """The resolved data directory, created if missing."""
    global _RESOLVED
    if _RESOLVED is None:
        env = (os.environ.get(ENV_VAR) or "").strip()
        if env:
            resolved = os.path.abspath(os.path.expanduser(env))
        elif _has_data(CODE_DIR):
            resolved = CODE_DIR          # existing side-by-side install
        else:
            resolved = _user_data_dir()
        _ensure_usable(resolved)
        _RESOLVED = resolved
    return _RESOLVED


def _ensure_usable(directory: str) -> None:
    """Create the data directory, or explain precisely why we cannot. This is
    the first thing that runs on a misconfigured container, so the message has
    to name the variable and the offending path rather than surfacing a bare
    FileExistsError from six frames down."""
    if os.path.exists(directory) and not os.path.isdir(directory):
        raise RuntimeError(
            f"{ENV_VAR} points at a file, not a directory: {directory}")
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as e:
        raise RuntimeError(
            f"Cannot create the data directory {directory}: {e.strerror}. "
            f"Set {ENV_VAR} to a writable location.") from e
    if not os.access(directory, os.W_OK):
        raise RuntimeError(
            f"The data directory {directory} is not writable. "
            f"Set {ENV_VAR} to a writable location.")


def data_file(name: str) -> str:
    """Absolute path to `name` inside the data directory."""
    return os.path.join(data_dir(), name)


def reset_cache() -> None:
    """Forget the resolved directory (tests, and after changing the env var)."""
    global _RESOLVED
    _RESOLVED = None


def describe() -> dict:
    """Where the data lives and why — surfaced by the CLI and /healthz."""
    env = (os.environ.get(ENV_VAR) or "").strip()
    if env:
        source = f"{ENV_VAR} environment variable"
    elif data_dir() == CODE_DIR:
        source = "alongside the application (existing install)"
    else:
        source = f"per-user application directory for {sys.platform}"
    return {"data_dir": data_dir(), "source": source, "code_dir": CODE_DIR}
