"""
Secret storage that works on every platform Log Masker runs on.

`keyring` is the right answer wherever there is a real credential store —
macOS Keychain, Windows Credential Manager, a Freedesktop Secret Service on a
desktop Linux session. It is *not* available on a headless Linux box, inside a
container, or over SSH without a D-Bus session, which is exactly where a shared
deployment lives. So secrets resolve through three tiers:

  1. **OS keyring** — used whenever it actually works.
  2. **Encrypted file** — ``secrets.enc`` in the data directory, Fernet-encrypted
     with a master key taken from ``LOGMASKER_MASTER_KEY`` or, failing that, a
     ``master.key`` file created next to it with owner-only permissions.
  3. **Environment variables** — read-only, and the natural way to inject keys
     into a container (``ANTHROPIC_API_KEY`` and friends).

Be clear-eyed about tier 2: a key file sitting beside the ciphertext protects
against another *user* on the machine and against a stray backup, not against
someone already running as you. On a server, set ``LOGMASKER_MASTER_KEY`` from
your secret manager so the key never touches the disk.
"""

import json
import os
import stat
from typing import Dict, Optional

from log_masker import paths

SERVICE = "log_masker"
SECRETS_FILE = "secrets.enc"
MASTER_KEY_FILE = "master.key"
MASTER_KEY_ENV = "LOGMASKER_MASTER_KEY"

# Set once probed, so a missing keyring backend costs one failed call, not one
# per lookup (the workspace reads keys on nearly every request).
_KEYRING: Optional[bool] = None


# ---------------------------------------------------------------------------
# Tier 1 — the OS credential store
# ---------------------------------------------------------------------------
def _keyring_ok() -> bool:
    global _KEYRING
    if _KEYRING is None:
        try:
            import keyring
            from keyring.backends.fail import Keyring as FailKeyring
            backend = keyring.get_keyring()
            # keyring installs a "fail" backend when nothing usable is present;
            # calling it raises, so treat it as unavailable up front.
            _KEYRING = not isinstance(backend, FailKeyring)
        except Exception:
            _KEYRING = False
    return bool(_KEYRING)


def _keyring_get(name: str) -> Optional[str]:
    if not _keyring_ok():
        return None
    try:
        import keyring
        return keyring.get_password(SERVICE, name)
    except Exception:
        return None


def _keyring_set(name: str, value: str) -> bool:
    if not _keyring_ok():
        return False
    try:
        import keyring
        keyring.set_password(SERVICE, name, value)
        return True
    except Exception:
        return False


def _keyring_delete(name: str) -> None:
    if not _keyring_ok():
        return
    try:
        import keyring
        keyring.delete_password(SERVICE, name)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Tier 2 — encrypted file
# ---------------------------------------------------------------------------
def _master_key() -> bytes:
    """The Fernet key protecting the secrets file, created on first use."""
    from cryptography.fernet import Fernet
    env = (os.environ.get(MASTER_KEY_ENV) or "").strip()
    if env:
        try:
            Fernet(env.encode())          # validate before anything depends on it
        except Exception:
            raise RuntimeError(
                f"{MASTER_KEY_ENV} is not a valid Fernet key. Generate one with:"
                "\n  python -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\"")
        return env.encode()
    path = paths.data_file(MASTER_KEY_FILE)
    try:
        with open(path, "r", encoding="utf-8") as f:
            key = f.read().strip()
        if key:
            return key.encode()
    except OSError:
        pass
    key = Fernet.generate_key()
    # Create it unreadable to anyone else before writing anything into it.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key.decode())
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)   # no-op on Windows ACLs
    except OSError:
        pass
    return key


def _file_load() -> Dict[str, str]:
    path = paths.data_file(SECRETS_FILE)
    if not os.path.exists(path):
        return {}
    try:
        from cryptography.fernet import Fernet
        with open(path, "rb") as f:
            data = json.loads(Fernet(_master_key()).decrypt(f.read()))
        return data if isinstance(data, dict) else {}
    except Exception:
        # A secrets file we cannot read is not a reason to take the app down;
        # the caller falls through to the environment.
        return {}


def _file_save(secrets: Dict[str, str]) -> bool:
    key = _master_key()          # raises with a precise message if misconfigured
    try:
        from cryptography.fernet import Fernet
        path = paths.data_file(SECRETS_FILE)
        blob = Fernet(key).encrypt(
            json.dumps(secrets, ensure_ascii=False).encode())
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
        os.replace(tmp, path)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def get_secret(name: str, env_var: str = "") -> Optional[str]:
    """A stored secret, or the value of `env_var` if nothing is stored."""
    value = _keyring_get(name)
    if value:
        return value.strip()
    value = _file_load().get(name)
    if value:
        return value.strip()
    if env_var:
        value = os.environ.get(env_var, "")
        if value:
            return value.strip()
    return None


def set_secret(name: str, value: str) -> str:
    """Store a secret; returns the backend that took it ("keyring"/"file").
    Raises RuntimeError when neither can hold it."""
    if not value:
        # An empty secret cannot be read back (get_secret treats it as absent),
        # so storing one would silently do nothing — in either tier.
        raise ValueError("Refusing to store an empty secret.")
    if _keyring_set(name, value):
        return "keyring"
    secrets = _file_load()
    secrets[name] = value
    if _file_save(secrets):
        return "file"
    raise RuntimeError(
        "No secret store is available: the OS keyring could not be reached and "
        "the encrypted file could not be written. Set the key in the "
        "environment instead, or point LOGMASKER_DATA_DIR at a writable "
        "directory.")


def delete_secret(name: str) -> None:
    """Remove a secret from every writable tier (the environment is not ours
    to clear — a key left in the environment keeps working, by design)."""
    _keyring_delete(name)
    secrets = _file_load()
    if secrets.pop(name, None) is not None:
        _file_save(secrets)


def backend() -> str:
    """Which tier writes land in — shown in the UI and by `cli.py status`."""
    if _keyring_ok():
        return "keyring"
    if os.environ.get(MASTER_KEY_ENV):
        return "encrypted file (master key from environment)"
    return "encrypted file"


def reset_cache() -> None:
    """Re-probe the keyring (tests)."""
    global _KEYRING
    _KEYRING = None
