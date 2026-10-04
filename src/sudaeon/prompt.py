"""Asking for the master password.

Three situations exist:

* **in the user's session** (dashboard, application gate, ``sudaeon
  permission``): a native GTK dialog is shown in-process,
* **root needs a user's answer** (the sentinel, triggered by a power button or
  a polkit denial): the sentinel talks to the per-session agent, which renders
  the dialog and relays the typed password back - the *sentinel* verifies it, so
  a tampered agent cannot approve anything,
* **no graphical session** (a plain TTY): a textual prompt with the same
  wording and the same three attempt limit.

The verification itself always happens through the setuid ``sudaeon-chkpwd``
(or, for the sentinel, its own privileged copy of the same check) so that rate
limiting and auditing are shared by every path.
"""

from __future__ import annotations

import getpass
import json
import os
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import paths, vault
from .util import log, run, username_of

TITLE_PERMISSION = "Sudaeon Permission Manager"
TITLE_DENIED = "Sudaeon Permission Manager - Access Denied"
TEXT_PERMISSION = "Please Enter the Master Password"
TEXT_INCORRECT = "The Password Entered was Incorrect"
TEXT_TOO_MANY = "The Password was incorrect too many times."

DEFAULT_ATTEMPTS = 3
AGENT_TIMEOUT = 120.0


@dataclass
class PromptResult:
    ok: bool
    reason: str = ""
    attempts: int = 0
    # The accepted password, kept only so the dashboard can hand it to the
    # privileged helper in the same unlock window.  It is never logged or
    # serialised (as_dict/__str__ deliberately omit it).
    password: str = ""

    def __bool__(self) -> bool:  # convenience for ``if request_permission(...)``
        return self.ok

    def __repr__(self) -> str:  # pragma: no cover - safety net for logging
        return (f"PromptResult(ok={self.ok}, reason={self.reason!r}, "
                f"attempts={self.attempts}, password=<hidden>)")


# ---------------------------------------------------------------------------
# verification (shared by every path)
# ---------------------------------------------------------------------------

def verify(password: str, *, recovery: bool = False) -> tuple[bool, int, str]:
    try:
        return vault.verify_master_via_chkpwd(password, recovery=recovery)
    except vault.VaultError as exc:
        return False, 2, str(exc)


def graphical_available() -> bool:
    if os.environ.get("SUDAEON_FORCE_TERMINAL"):
        return False
    if not (os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY")):
        return False
    try:
        import gi  # noqa: F401
        gi.require_version("Gtk", "4.0")
        from gi.repository import Gtk  # noqa: F401
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# terminal prompt
# ---------------------------------------------------------------------------

def terminal_ask(action: str = "", *, attempts: int = DEFAULT_ATTEMPTS,
                 prefix: str = "[Sudaeon]", text: str = "Please Enter the Master Password:",
                 quiet: bool = False) -> PromptResult:
    """The terminal workflow: prompt, verify, retry, then give up."""
    stream = sys.stderr
    for attempt in range(1, attempts + 1):
        try:
            password = getpass.getpass(f"{prefix}: {text} ")
        except (EOFError, KeyboardInterrupt):
            if not quiet:
                print("", file=stream)
            return PromptResult(False, "cancelled", attempt)
        ok, code, message = verify(password)
        if ok:
            return PromptResult(True, "ok", attempt)
        if code == 3:
            if not quiet:
                print("Sudaeon: too many incorrect attempts. Please wait and try again.",
                      file=stream)
            return PromptResult(False, "locked", attempt)
        if code != 1:
            if not quiet:
                print(f"Sudaeon: {message or 'the master password could not be verified'}",
                      file=stream)
            return PromptResult(False, "error", attempt)
        if not quiet:
            print(TEXT_INCORRECT, file=stream)
    if not quiet:
        print(TEXT_TOO_MANY, file=stream)
    return PromptResult(False, "too-many", attempts)


# ---------------------------------------------------------------------------
# in-process GTK prompt
# ---------------------------------------------------------------------------

def gtk_ask(verb: str = "", *, attempts: int = DEFAULT_ATTEMPTS,
            title: str = TITLE_PERMISSION, text: str = TEXT_PERMISSION) -> PromptResult:
    from .gui import prompt_window
    return prompt_window.ask(verb=verb, attempts=attempts, title=title, text=text)


# ---------------------------------------------------------------------------
# the agent protocol (root <-> user session)
# ---------------------------------------------------------------------------

def send_to_agent(uid: int, request: dict[str, Any], *,
                  timeout: float = AGENT_TIMEOUT) -> dict[str, Any] | None:
    """Send one request to the per-session agent of ``uid``."""
    path = paths.agent_socket(uid)
    if not path.exists():
        return None
    payload = (json.dumps(request) + "\n").encode()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(path))
            sock.sendall(payload)
            chunks = []
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
                if b"\n" in data:
                    break
    except (OSError, socket.timeout) as exc:
        log(f"agent {uid}: {exc}")
        return None
    try:
        return json.loads(b"".join(chunks).decode(errors="replace").strip() or "{}")
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# the entry point used by the rest of the program
# ---------------------------------------------------------------------------

def request_permission(verb: str = "complete this action", *, action: str = "",
                       user: str = "", uid: int | None = None, attempts: int | None = None,
                       title: str = TITLE_PERMISSION, text: str = TEXT_PERMISSION,
                       allow_app_override: bool = False, source: str = "cli") -> bool:
    """Obtain the master password from whichever interface is available."""
    from . import audit, config
    uid = os.getuid() if uid is None else uid
    if attempts is None:
        policy = vault.load_policy() or config.default_policy()
        attempts = int(policy.get("enforcement", {}).get("terminal_max_attempts", 3))
    user = user or username_of(uid) or "?"

    if graphical_available():
        result = gtk_ask(verb, attempts=attempts, title=title, text=text)
    else:
        result = terminal_ask(f"{verb}: " if verb else "", attempts=attempts)

    audit.append(f"permission:{action or verb}", "master-ok" if result.ok else "master-fail",
                 user=user, uid=uid, source=source,
                 detail=result.reason or ("accepted" if result.ok else "denied"))
    return result.ok


def request_permission_via_agent(uid: int, verb: str, *, action: str = "",
                                 timeout: float = AGENT_TIMEOUT,
                                 attempts: int = DEFAULT_ATTEMPTS) -> PromptResult:
    """(root) Ask the user's session agent to collect the password.

    The agent only relays what was typed; the caller verifies it.
    """
    response = send_to_agent(uid, {
        "kind": "collect",
        "verb": verb,
        "action": action,
        "title": TITLE_PERMISSION,
        "text": TEXT_PERMISSION,
        "attempts": attempts,
        "timeout": timeout,
    }, timeout=timeout + 10)
    if response is None:
        return PromptResult(False, "agent-unavailable")
    if response.get("ok"):
        password = response.get("password") or ""
        ok, code, _message = verify(password)
        if ok:
            return PromptResult(True, "ok")
        if code == 3:
            return PromptResult(False, "locked")
        return PromptResult(False, "incorrect")
    return PromptResult(False, str(response.get("reason") or "denied"))
