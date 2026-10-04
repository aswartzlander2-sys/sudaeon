"""Password capture dialogs used by the dashboard.

The Permission Manager windows (:mod:`sudaeon.gui.prompt_window`) are the user
facing dialogs; these helpers just wrap them so the dashboard can keep the
accepted password for the privileged helper calls made in the same unlock
window.  Nothing here is written to disk or to the audit log.
"""

from __future__ import annotations

from typing import Any

from .. import prompt, vault
from . import prompt_window


def capture(parent: Any = None, *, verb: str = "", attempts: int | None = None) -> str | None:
    """Ask for the master password and return the text, or ``None`` if not given."""
    if attempts is None:
        policy = vault.load_policy() or {}
        attempts = int(policy.get("enforcement", {}).get("terminal_max_attempts",
                                                         prompt.DEFAULT_ATTEMPTS))
    result = prompt_window.ask(verb or "Please confirm your identity", parent=parent,
                               attempts=int(attempts))
    if result.ok and result.password:
        return result.password
    return None


def capture_new(parent: Any = None, *, title: str = "New Master Password") -> str | None:
    """Ask twice for a new master password."""
    return prompt_window.ask_new_password(title=title, parent=parent)
