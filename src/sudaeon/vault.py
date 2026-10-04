"""Master password vault.

Files created by ``sudaeon install`` (all inside ``/var/lib/sudaeon``)
---------------------------------------------------------------------
``vault.enc``          Encrypted container (ChaCha20-Poly1305) holding a copy of
                       the master verifier, the recovery key, policy metadata
                       and the recovery history.  This is the "encrypted file"
                       requested by the design: the master password itself is
                       never written anywhere, in clear or encrypted form - it
                       is only ever *derived from*.
``master.verifier``    Salted scrypt digest of the master password (0600 root).
``recovery.verifier``  SHA-256 digest of the recovery key (0600 root).
``policy.json``        The active policy (0644, no secrets).
``enforcement.conf``   Flat rendering of the policy for the PAM module.

Verification always goes through the setuid ``sudaeon-chkpwd`` binary so that
there is exactly one implementation of the password check (with rate limiting
and auditing) for both C and Python callers.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from . import crypto, paths
from .util import atomic_write, now_iso, read_json, run, write_json

VAULT_VERSION = 1


class VaultError(Exception):
    """Raised for unrecoverable vault problems."""


# ---------------------------------------------------------------------------
# policy file helpers
# ---------------------------------------------------------------------------

def load_policy(log=None) -> dict[str, Any] | None:
    from . import config
    raw = read_json(paths.POLICY_FILE, None)
    if raw is None:
        return None
    policy = config.normalize_policy(raw)
    if log is not None:
        for problem in config.validate_policy(policy):
            log(f"policy warning: {problem}")
    return policy


def save_policy(policy: dict[str, Any], *, backup: bool = True) -> None:
    from . import config
    policy = config.normalize_policy(policy)
    if backup and paths.POLICY_FILE.exists():
        try:
            shutil.copy2(paths.POLICY_FILE, paths.POLICY_BAK)
            os.chmod(paths.POLICY_BAK, 0o644)
        except OSError:
            pass
    write_json(paths.POLICY_FILE, policy, mode=0o644)


# ---------------------------------------------------------------------------
# verifiers
# ---------------------------------------------------------------------------

def read_master_record() -> dict[str, Any] | None:
    return read_json(paths.MASTER_VERIFIER, None)


def write_master_record(record: dict[str, Any]) -> None:
    write_json(paths.MASTER_VERIFIER, record, mode=0o600)


def read_recovery_record() -> dict[str, Any] | None:
    return read_json(paths.RECOVERY_VERIFIER, None)


def write_recovery_record(key: str) -> str:
    digest = crypto.recovery_key_digest(key)
    write_json(paths.RECOVERY_VERIFIER,
               {"version": 1, "algorithm": "sha256", "digest": digest, "created": now_iso()},
               mode=0o600)
    return digest


def recovery_key_matches(key: str) -> bool:
    record = read_recovery_record()
    if not isinstance(record, dict):
        return False
    try:
        import hmac
        digest = crypto.recovery_key_digest(key)
    except ValueError:
        return False
    stored = str(record.get("digest", ""))
    return hmac.compare_digest(digest, stored)


# ---------------------------------------------------------------------------
# password verification (delegated to the setuid helper for one implementation)
# ---------------------------------------------------------------------------

def chkpwd_binary() -> Path | None:
    for candidate in (paths.CHKPWD_BIN, Path("/usr/lib/sudaeon/sudaeon-chkpwd"),
                      Path(__file__).resolve().parent / ".." / ".." / "build" / "sudaeon-chkpwd"):
        if candidate.exists():
            return candidate
    return None


def verify_master_via_chkpwd(password: str, *, recovery: bool = False,
                             timeout: float = 30.0) -> tuple[bool, int, str]:
    """Ask the setuid verifier.  Returns (ok, exit_code, stderr)."""
    binary = chkpwd_binary()
    if binary is None:
        raise VaultError("sudaeon-chkpwd is not installed")
    argv = [str(binary)]
    if recovery:
        argv.append("--recovery")
    proc = run(argv, input_text=password + "\n", timeout=timeout)
    err = (proc.stderr or b"").decode(errors="replace").strip()
    return proc.returncode == 0, proc.returncode, err


def verify_master(password: str) -> bool:
    """Verify the master password (rate limited + audited by chkpwd)."""
    ok, _code, _err = verify_master_via_chkpwd(password)
    return ok


def verify_password_python(password: str) -> bool:
    """Verification without the setuid helper (root/tests only)."""
    record = read_master_record()
    if record is None:
        raise VaultError("no master password has been set")
    return crypto.verify_password(password, record)


# ---------------------------------------------------------------------------
# vault contents
# ---------------------------------------------------------------------------

def _vault_payload(master_record: dict[str, Any], recovery_key: str,
                   policy: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "version": VAULT_VERSION,
        "created": now_iso(),
        "master_verifier": master_record,
        "recovery_key": recovery_key,
        "recovery_created": now_iso(),
        "policy": policy,
        "history": [],
    }


def vault_exists() -> bool:
    return paths.VAULT_FILE.exists()


def write_vault(password: str, payload: dict[str, Any], *,
                params: dict[str, Any] | None = None) -> None:
    params = params or (payload.get("master_verifier") or {}) or None
    blob = crypto.encrypt_vault(password, payload, params=params)
    atomic_write(paths.VAULT_FILE, blob, mode=0o600)


def read_vault(password: str) -> dict[str, Any]:
    try:
        blob = paths.VAULT_FILE.read_bytes()
    except OSError as exc:
        raise VaultError(f"cannot read vault: {exc}") from exc
    try:
        payload = crypto.decrypt_vault(password, blob)
    except crypto.CryptoError as exc:
        raise VaultError("the master password does not open the vault") from exc
    if not isinstance(payload, dict):
        raise VaultError("vault payload is malformed")
    return payload


def vault_readable(password: str) -> bool:
    try:
        read_vault(password)
        return True
    except VaultError:
        return False


# ---------------------------------------------------------------------------
# provisioning / rotation
# ---------------------------------------------------------------------------

def provision(password: str, policy: dict[str, Any], *,
              params: dict[str, Any] | None = None, recovery_key: str | None = None,
              make_recovery: bool = True) -> dict[str, Any]:
    """Create master verifier, recovery key, recovery verifier and vault."""
    from . import config as config_mod

    params = crypto.check_kdf(params or (policy.get("advanced", {}).get("master_kdf")
                                         or crypto.DEFAULT_KDF))
    record = crypto.make_verifier(password, params)
    paths.STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(paths.STATE_DIR, 0o755)
    write_master_record(record)

    if recovery_key is None and make_recovery:
        recovery_key = crypto.generate_recovery_key()
    if recovery_key:
        write_recovery_record(recovery_key)

    payload = _vault_payload(record, recovery_key or "", policy)
    write_vault(password, payload, params=params)
    return {"master_record": record, "recovery_key": recovery_key or ""}


def change_master(old_password: str, new_password: str, *,
                  params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Rotate the master password, re-encrypting the vault."""
    payload = read_vault(old_password)
    kdf = crypto.check_kdf(params or (payload.get("master_verifier") or crypto.DEFAULT_KDF))
    record = crypto.make_verifier(new_password, kdf)
    payload["master_verifier"] = record
    payload["updated"] = now_iso()
    history = payload.setdefault("history", [])
    if isinstance(history, list):
        history.append({"ts": now_iso(), "event": "master password changed"})
        del history[:-20]
    write_master_record(record)
    write_vault(new_password, payload, params=kdf)
    return {"master_record": record, "recovery_key": payload.get("recovery_key", "")}


def reset_master(new_password: str, *, recovery_key: str | None = None,
                 params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Set a new master password.

    * with ``recovery_key`` the recovery verifier must match,
    * without it the caller must be root (``--force``); a fresh recovery key is
      generated and a note is written to the vault history.
    """
    payload: dict[str, Any]
    if recovery_key:
        if not recovery_key_matches(recovery_key):
            raise VaultError("the recovery key is not correct")
        policy = load_policy()
        keep_recovery = crypto.normalize_recovery_key(recovery_key)
        payload = {
            "version": VAULT_VERSION,
            "created": now_iso(),
        }
        history = [{"ts": now_iso(), "event": "master password reset with recovery key"}]
    else:
        if os.geteuid() != 0:
            raise VaultError("resetting without the recovery key requires root")
        policy = load_policy()
        keep_recovery = crypto.generate_recovery_key()
        payload = {"version": VAULT_VERSION, "created": now_iso()}
        history = [{"ts": now_iso(),
                    "event": "master password force-reset by root",
                    "uid": os.getuid()}]

    kdf = crypto.check_kdf(params or ((policy or {}).get("advanced", {}).get("master_kdf")
                                      or crypto.DEFAULT_KDF))
    record = crypto.make_verifier(new_password, kdf)
    payload.update({
        "master_verifier": record,
        "recovery_key": keep_recovery,
        "recovery_created": now_iso(),
        "policy": policy,
        "history": history,
    })
    write_master_record(record)
    if not recovery_key:
        write_recovery_record(keep_recovery)
    write_vault(new_password, payload, params=kdf)
    return {"master_record": record, "recovery_key": keep_recovery}


def recover_vault_key(password: str, recovery_key: str) -> dict[str, Any]:
    """Re-create the vault after a reset using the recovery key."""
    return reset_master(password, recovery_key=recovery_key)


def show_recovery_key(password: str) -> str:
    payload = read_vault(password)
    key = payload.get("recovery_key") or ""
    if not key:
        raise VaultError("no recovery key is stored in the vault")
    return key


def regenerate_recovery_key(password: str) -> str:
    payload = read_vault(password)
    key = crypto.generate_recovery_key()
    payload["recovery_key"] = key
    payload["recovery_created"] = now_iso()
    write_recovery_record(key)
    write_vault(password, payload)
    return key


def repair(password: str, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Rewrite the vault from the master verifier (used to heal the vault)."""
    record = read_master_record()
    if record is None:
        raise VaultError("no master verifier - run 'sudaeon reset-password --force' as root")
    if not crypto.verify_password(password, record):
        raise VaultError("the master password does not match the verifier")
    recovery = ""
    existing = read_recovery_record() or {}
    # we cannot recover the plaintext recovery key from its digest; generate one
    recovery = crypto.generate_recovery_key()
    write_recovery_record(recovery)
    payload = _vault_payload(record, recovery, policy)
    payload["history"] = [{"ts": now_iso(), "event": "vault repaired",
                           "previous_recovery_digest": existing.get("digest", "")}]
    write_vault(password, payload)
    return {"recovery_key": recovery}


def vault_info() -> dict[str, Any]:
    """Non-secret information about the vault for the dashboard."""
    info: dict[str, Any] = {
        "path": str(paths.VAULT_FILE),
        "exists": paths.VAULT_FILE.exists(),
        "bytes": None,
        "master_verifier": str(paths.MASTER_VERIFIER),
        "master_verifier_exists": paths.MASTER_VERIFIER.exists(),
        "recovery_verifier_exists": paths.RECOVERY_VERIFIER.exists(),
        "created": None,
    }
    try:
        stat = paths.VAULT_FILE.stat()
        info["bytes"] = stat.st_size
        from datetime import datetime, timezone
        info["created"] = datetime.fromtimestamp(stat.st_mtime, timezone.utc).replace(
            microsecond=0).isoformat()
        info["mode"] = oct(stat.st_mode & 0o777)
        info["owner_uid"] = stat.st_uid
    except OSError:
        pass
    record = read_master_record()
    if isinstance(record, dict):
        info["kdf"] = record.get("kdf")
        info["kdf_n"] = record.get("n")
        info["kdf_r"] = record.get("r")
        info["kdf_p"] = record.get("p")
        info["password_set"] = bool(record.get("hash"))
    return info
