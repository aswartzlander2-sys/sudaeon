"""Privilege handling: how the unprivileged parts of Sudaeon reach root.

Three paths exist, in order of preference:

1. ``sudaeon-helper`` invoked through ``sudo -n`` using the passwordless
   sudoers entry created at install time (administrators only).  This is the
   fast, prompt free path used by the dashboard after it has verified the
   master password itself.
2. ``pkexec`` with the ``com.sudaeon.manage`` polkit action (any administrative
   user, shows the native Ubuntu authentication dialog).  Used during install
   and whenever the sudoers entry is missing.
3. Refusing to act - the helper is the only writer of privileged state.

The master password is never passed on the command line: it goes through the
helper's stdin.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from . import paths
from .util import (debug, error, have, invoking_uid, is_root, log, run, username_of,
                   which)


class PrivilegeError(Exception):
    """Raised when the helper cannot be reached or returns an error."""


@dataclass
class HelperResult:
    ok: bool
    message: str = ""
    data: dict[str, Any] | None = None
    error: str = ""
    raw: str = ""

    @classmethod
    def from_json(cls, text: str) -> "HelperResult":
        text = text.strip()
        if not text:
            return cls(False, error="the helper returned no output")
        try:
            payload = json.loads(text.splitlines()[-1])
        except ValueError:
            return cls(False, error=f"unexpected helper output: {text[:200]}", raw=text)
        return cls(bool(payload.get("ok")), payload.get("message", ""),
                   payload.get("data"), payload.get("error", ""), text)


def helper_binary() -> Path:
    """Locate the helper (installed path first, repository build second)."""
    for candidate in (paths.HELPER_BIN, Path("/usr/lib/sudaeon/sudaeon-helper")):
        if candidate.exists():
            return candidate
    fallback = paths.PACKAGE_DIR / "helper.py"
    return fallback


def helper_available() -> bool:
    return helper_binary().exists()


def escalation_argv(verb: str, args: Sequence[str] = ()) -> list[str] | None:
    """Build a command line that runs ``sudaeon-helper <verb>`` as root."""
    if is_root():
        return None                      # caller is already root; run directly
    helper = str(helper_binary())
    if have("sudo"):
        # -n: never prompt; the sudoers entry installed by Sudaeon covers admins
        return ["sudo", "-n", helper, verb, *args]
    if have("pkexec"):
        return ["pkexec", helper, verb, *args]
    return None


def can_escalate() -> bool:
    if is_root():
        return True
    if have("sudo") or have("pkexec"):
        return True
    return False


def helper_command(verb: str, args: Sequence[str] = (), *,
                   prefer_pkexec: bool = False) -> list[str] | None:
    if is_root():
        return [str(helper_binary()), verb, *args]
    helper = str(helper_binary())
    pkexec = ["pkexec", helper, verb, *args] if have("pkexec") else None
    sudo = ["sudo", "-n", helper, verb, *args] if have("sudo") else None
    if prefer_pkexec:
        return pkexec or sudo
    return sudo or pkexec


def call_helper(verb: str, args: Sequence[str] = (), *, stdin: str | None = None,
                prefer_pkexec: bool = False, timeout: float = 120.0,
                env: dict[str, str] | None = None) -> HelperResult:
    """Run a helper verb, returning the parsed result.

    Raises :class:`PrivilegeError` when no escalation path exists.
    """
    argv = helper_command(verb, args, prefer_pkexec=prefer_pkexec)
    if argv is None:
        raise PrivilegeError("Sudaeon is not installed, or sudo/pkexec is unavailable")
    if not is_root() and not paths.HELPER_BIN.exists():
        raise PrivilegeError("the Sudaeon helper is not installed")
    debug(f"helper: {' '.join(shlex.quote(part) for part in argv)}")
    child_env = dict(os.environ) if env is None else env
    # never leak a sandbox override into a privileged helper call
    child_env.pop("SUDAEON_ROOT", None)
    try:
        proc = subprocess.run(
            argv,
            input=(stdin or "").encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=child_env,
        )
    except subprocess.TimeoutExpired as exc:
        raise PrivilegeError(f"the helper timed out after {timeout:.0f}s") from exc
    except FileNotFoundError as exc:
        raise PrivilegeError(f"cannot run {argv[0]}: {exc}") from exc

    stdout = (proc.stdout or b"").decode(errors="replace")
    stderr = (proc.stderr or b"").decode(errors="replace")
    result = HelperResult.from_json(stdout or "{}")
    if proc.returncode != 0 and result.ok:
        result.ok = False
        result.error = stderr.strip() or f"helper exited with {proc.returncode}"
    if not result.error and not result.ok:
        result.error = stderr.strip() or f"helper exited with {proc.returncode}"
    if result.error and stderr and result.error not in stderr:
        result.error = f"{result.error}".strip()
    return result


def call_helper_with_master(verb: str, password: str, payload: dict[str, Any] | None = None,
                            args: Sequence[str] = (), **kwargs) -> HelperResult:
    """Send the master password on the first stdin line plus an optional JSON body."""
    body = json.dumps(payload) if payload is not None else ""
    stdin = password + "\n" + body
    return call_helper(verb, args, stdin=stdin, **kwargs)


def direct_helper(argv: Sequence[str], *, stdin: str | None = None,
                  timeout: float = 120.0) -> subprocess.CompletedProcess:
    """Run a helper command exactly as given (used by the helper itself)."""
    return run(list(argv), input_text=stdin, timeout=timeout)


def am_i_admin() -> bool:
    """Is the invoking user allowed to open the dashboard?"""
    from . import users
    from . import vault
    policy = vault.load_policy()
    if policy is None:
        return False
    name = username_of(invoking_uid())
    if not name:
        return False
    from . import config
    return config.can_open_dashboard(policy, name)


def dashboard_entry_allowed() -> tuple[bool, str]:
    """Check whether the dashboard may be opened for the invoking user."""
    from . import config, installstate, vault
    if not installstate.is_installed():
        return True, "not installed"
    policy = vault.load_policy()
    if policy is None:
        return True, "no policy yet"
    name = username_of(invoking_uid())
    if not name:
        return False, "your account could not be identified"
    if name == "root" or is_root():
        return True, "root"
    if config.can_open_dashboard(policy, name):
        return True, "administrator"
    return False, (f"Only administrators can open the Sudaeon dashboard. "
                   f"'{name}' is a {config.ROLE_LABELS.get(config.role_for(policy, name), 'user')}.")


def describe_escalation() -> str:
    if is_root():
        return "running as root"
    if have("sudo") and paths.HELPER_BIN.exists():
        return "sudo (passwordless for Sudaeon administrators)"
    if have("pkexec"):
        return "pkexec (Ubuntu authentication dialog)"
    return "no escalation mechanism available"
