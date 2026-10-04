"""The enforcement engine: one place that decides whether an action is allowed.

Every component (helper, PAM module, polkit guard, sentinel, GUI, CLI) funnels
through this logic, either directly (Python) or through the pre-rendered
``enforcement.conf`` (C PAM module).  Keeping a single implementation means the
dashboard can always explain why something happened.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from . import config
from . import schedule as schedule_mod
from .util import username_of


@dataclass(frozen=True)
class Decision:
    action: str
    label: str
    allowed: bool
    require_master: bool
    reason: str
    user: str
    role: str
    subject: bool
    bypass: bool
    verb: str
    uid: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "label": self.label,
            "allowed": self.allowed,
            "require_master": self.require_master,
            "reason": self.reason,
            "user": self.user,
            "uid": self.uid,
            "role": self.role,
            "subject": self.subject,
            "bypass": self.bypass,
            "verb": self.verb,
        }


def _allow(spec: config.Action, user: str, role: str, subject: bool, reason: str,
           uid: int | None) -> Decision:
    return Decision(spec.key, spec.label, True, False, reason, user, role, subject,
                    spec.bypass, spec.prompt_verb, uid)


def _deny(spec: config.Action, user: str, role: str, subject: bool, reason: str,
          uid: int | None) -> Decision:
    return Decision(spec.key, spec.label, False, spec.bypass, reason, user, role, subject,
                    spec.bypass, spec.prompt_verb, uid)


def evaluate(policy: dict[str, Any], key: str, username: str | None = None,
             uid: int | None = None, when: datetime | None = None) -> Decision:
    """Decide whether ``username`` may perform action ``key`` right now."""
    spec = config.action(key)
    if username is None:
        username = username_of(uid if uid is not None else 0) or "unknown"
    role = config.role_for(policy, username)
    subject = config.is_subject(policy, username)

    if not policy.get("enabled"):
        return _allow(spec, username, role, subject, "Sudaeon is turned off", uid)
    if not config.role_for(policy, username) == "root" and not subject:
        if role == config.ROLE_EXEMPT:
            return _allow(spec, username, role, subject, "user is exempt from policy", uid)
        if role == config.ROLE_ADMIN:
            return _allow(spec, username, role, subject,
                          "administrators are exempt from policy", uid)
        return _allow(spec, username, role, subject, f"role {role} is not restricted", uid)
    if not schedule_mod.active_now(policy.get("schedule"), when):
        return _allow(spec, username, role, subject,
                      "outside of the enforcement schedule", uid)

    if config.action_allowed(policy, key):
        return _allow(spec, username, role, subject, f"{spec.label} is allowed", uid)

    if spec.bypass:
        reason = f"{spec.label.replace('Allow ', '')} is blocked by Sudaeon policy"
    else:
        reason = f"{spec.label} is blocked by Sudaeon policy (no override)"
    return _deny(spec, username, role, subject, reason, uid)


# ---------------------------------------------------------------------------
# mapping of foreign action namespaces onto Sudaeon actions
# ---------------------------------------------------------------------------

POLKIT_PREFIXES: tuple[tuple[str, str], ...] = (
    ("org.freedesktop.login1.", "power"),
    ("org.freedesktop.accounts.", "user_management"),
    ("org.gnome.controlcenter.user-accounts", "user_management"),
    ("org.debian.apt.", "package_management"),
    ("org.freedesktop.packagekit.", "package_management"),
    ("org.gnome.software.", "package_management"),
    ("org.freedesktop.udisks2.", "removable_media"),
    ("org.freedesktop.policykit.exec", "polkit_admin"),
    ("org.gnome.controlcenter.", "polkit_admin"),
    ("org.gnome.settings-daemon.", "polkit_admin"),
    ("org.freedesktop.NetworkManager.", "polkit_admin"),
    ("org.freedesktop.hostname1.", "polkit_admin"),
    ("org.freedesktop.locale1.", "polkit_admin"),
    ("org.freedesktop.timedate1.", "polkit_admin"),
    ("org.freedesktop.systemd1.", "polkit_admin"),
    ("org.opensuse.cupspkhelper.", "polkit_admin"),
    ("org.freedesktop.color-manager.", "polkit_admin"),
    ("org.freedesktop.bolt.", "polkit_admin"),
    ("com.ubuntu.", "polkit_admin"),
    ("io.systemd.", "polkit_admin"),
)

_LOGIND_ACTIONS = {
    "reboot": "reboot",
    "power-off": "poweroff",
    "halt": "halt",
    "suspend": "suspend",
    "hibernate": "hibernate",
    "hybrid-sleep": "hybrid_sleep",
    "suspend-then-hibernate": "suspend_then_hibernate",
    "kexec": "kexec",
    "soft-reboot": "soft_reboot",
}


def action_for_polkit(action_id: str) -> str | None:
    """Map a polkit action id onto a Sudaeon action key (``None`` = unmanaged)."""
    if not action_id:
        return None
    if action_id.startswith("org.freedesktop.login1."):
        remainder = action_id[len("org.freedesktop.login1."):]
        for suffix in ("-multiple-sessions", "-ignore-inhibit"):
            if remainder.endswith(suffix):
                remainder = remainder[: -len(suffix)]
                break
        return _LOGIND_ACTIONS.get(remainder)
    for prefix, key in POLKIT_PREFIXES:
        if action_id.startswith(prefix):
            if key == "power":
                continue
            return key
    return None


PAM_SERVICES: dict[str, str] = {
    "sudo": "sudo",
    "sudo-i": "sudo",
    "su": "sudo",
    "su-l": "sudo",
    "pkexec": "sudo",
    "polkit-1": "sudo",
    "passwd": "user_management",
    "chfn": "user_management",
    "chsh": "user_management",
    "gpasswd": "user_management",
    "chpasswd": "user_management",
    "useradd": "user_management",
    "usermod": "user_management",
    "login": "root_login",
    "gdm-password": "root_login",
    "gdm-launch-environment": "root_login",
    "lightdm": "root_login",
    "sddm": "root_login",
    "sshd": "root_login",
}


def action_for_pam(service: str, pam_user: str | None = None) -> str | None:
    key = PAM_SERVICES.get(service)
    if key is None:
        return None
    if key == "root_login" and pam_user not in {"root", None}:
        return None
    return key


def explain(policy: dict[str, Any], username: str) -> list[tuple[str, str, str]]:
    """Rows of (action label, state, reason) for the dashboard / CLI status."""
    rows: list[tuple[str, str, str]] = []
    role = config.role_for(policy, username)
    subject = config.is_subject(policy, username)
    for spec in config.actions():
        if spec.group in {"session", "applications"}:
            continue
        allowed = config.action_allowed(policy, spec.key)
        if not policy.get("enabled"):
            state = "not enforced (Sudaeon off)"
        elif not subject:
            state = f"not enforced ({config.ROLE_LABELS.get(role, role)})"
        elif not schedule_mod.active_now(policy.get("schedule")):
            state = "not enforced (outside schedule)"
        else:
            state = "allowed" if allowed else (
                "requires master password" if spec.bypass else "blocked")
        rows.append((spec.label, state, f"{spec.group}"))
    return rows
