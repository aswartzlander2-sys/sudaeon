"""Policy model for Sudaeon: defaults, validation and rendering.

The policy is stored as plain JSON in ``/var/lib/sudaeon/policy.json`` (mode
0644 - it contains no secrets).  It is the single source of truth for:

* the dashboard (what to show, what is greyed out),
* the enforcement engine used by the helper, the sentinel and the polkit
  guard, and
* the flat ``enforcement.conf`` consumed by the C PAM module, which cannot
  parse JSON.

Roles
-----
Every account has exactly one role:

``admin``     Administrator - may open the dashboard (after entering the master
              password).  Policy still applies unless "Exempt administrators"
              is enabled.
``exempt``    Exempt from Policy - policy does not apply to this account.
``regular``   Regular User - policy applies, no dashboard access.
``root``      Implicit: the root account and uid 0 are never restricted (it is
              not possible to enforce anything reliably against root and
              pretending otherwise would be security theatre).
"""

from __future__ import annotations

import copy
import re
from typing import Any, Iterable

from . import schedule as schedule_mod
from .util import is_admin_user, now_iso

SCHEMA = 1
TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")

ROLE_ADMIN = "admin"
ROLE_EXEMPT = "exempt"
ROLE_REGULAR = "regular"
ROLES = (ROLE_ADMIN, ROLE_EXEMPT, ROLE_REGULAR)
ROLE_LABELS = {
    ROLE_ADMIN: "Administrator",
    ROLE_EXEMPT: "Exempt from Policy",
    ROLE_REGULAR: "Regular User",
}
ROLE_DESCRIPTIONS = {
    ROLE_ADMIN: "Full access to the Sudaeon dashboard. Policy still applies to this user.",
    ROLE_EXEMPT: "Sudaeon policy does not apply to this user. No dashboard access.",
    ROLE_REGULAR: "Sudaeon policy applies to this user. No dashboard access.",
}

POWER_BUTTON_MODES = ("disable", "require_master", "allow")
POWER_BUTTON_LABELS = {
    "disable": "Disable",
    "require_master": "Require Master Password",
    "allow": "Allow",
}

ENFORCE_ALWAYS = "always"
ENFORCE_DURING = "enforce_during"
ENFORCE_OUTSIDE = "enforce_outside"


# ---------------------------------------------------------------------------
# action registry
# ---------------------------------------------------------------------------

class Action:
    """Metadata describing one controllable action."""

    __slots__ = ("key", "label", "group", "description", "default", "logind", "polkit",
                 "prompt_verb", "bypass", "dconf")

    def __init__(self, key: str, label: str, group: str, *, default: bool = True,
                 description: str = "", logind: str | None = None, polkit: Iterable[str] = (),
                 prompt_verb: str = "complete this action", bypass: bool = True,
                 dconf: tuple[str, str] | None = None) -> None:
        self.key = key
        self.label = label
        self.group = group
        self.default = default
        self.description = description
        self.logind = logind
        self.polkit = tuple(polkit)
        self.prompt_verb = prompt_verb
        self.bypass = bypass
        self.dconf = dconf


_LOGIND_SUFFIXES = ("", "-multiple-sessions", "-ignore-inhibit")


def _logind(base: str) -> tuple[str, ...]:
    return tuple(f"org.freedesktop.login1.{base}{suffix}" for suffix in _LOGIND_SUFFIXES)


DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")

ACTIONS: dict[str, Action] = {}


def _register(action: Action) -> None:
    ACTIONS[action.key] = action


for _key, _label, _base, _verb in (
    ("reboot", "Allow Rebooting", "reboot", "restart the computer"),
    ("poweroff", "Allow Shutdowns", "power-off", "shut down the computer"),
    ("halt", "Allow Halt (System Down Without Power Off)", "halt", "halt the computer"),
    ("suspend", "Allow Suspend", "suspend", "suspend the computer"),
    ("hibernate", "Allow Hibernation", "hibernate", "hibernate the computer"),
    ("hybrid_sleep", "Allow Hybrid Sleep", "hybrid-sleep", "put the computer into hybrid sleep"),
    ("suspend_then_hibernate", "Allow Suspend Then Hibernate", "suspend-then-hibernate",
     "suspend the computer"),
):
    _register(Action(_key, _label, "power", logind=_base, polkit=_logind(_base),
                     prompt_verb=_verb))

_register(Action("kexec", "Allow kexec (Boot Another Kernel)", "power",
                 logind="kexec", polkit=_logind("kexec"),
                 prompt_verb="start another kernel"))
_register(Action("soft_reboot", "Allow Soft Reboot (systemd Only)", "power",
                 logind="soft-reboot", polkit=("org.freedesktop.login1.soft-reboot",),
                 prompt_verb="soft reboot the computer"))

# Session level controls.  On Ubuntu these are enforced through the GNOME
# lockdown keys (they are the only supported system-wide switch for them).
_register(Action("log_out", "Allow Logging Out", "session",
                 dconf=("org.gnome.desktop.lockdown", "disable-log-out"),
                 prompt_verb="log out"))
_register(Action("lock_screen", "Allow Locking the Screen", "session",
                 dconf=("org.gnome.desktop.lockdown", "disable-lock-screen"),
                 prompt_verb="lock the screen"))
_register(Action("switch_user", "Allow Switching Users", "session",
                 dconf=("org.gnome.desktop.lockdown", "disable-user-switching"),
                 prompt_verb="switch users"))
_register(Action("command_line", "Allow the GNOME Command Line (Alt+F2)", "session",
                 default=True,
                 dconf=("org.gnome.desktop.lockdown", "disable-command-line"),
                 prompt_verb="use the command line"))
_register(Action("printing", "Allow Printing", "session",
                 dconf=("org.gnome.desktop.lockdown", "disable-printing"),
                 prompt_verb="print"))
_register(Action("save_to_disk", "Allow Saving Files to Disk", "session",
                 dconf=("org.gnome.desktop.lockdown", "disable-save-to-disk"),
                 prompt_verb="save files to disk"))

# Administrative / terminal enforcement (the "Enforcement" tab).
_register(Action("sudo", "Block Terminal from completing Sudo actions", "enforcement",
                 default=False, prompt_verb="run a privileged command",
                 description="Every sudo, su or pkexec in a terminal additionally requires "
                             "the master password."))
_register(Action("user_management", "Block User Account Changes", "enforcement", default=False,
                 prompt_verb="change user accounts",
                 description="Blocks passwd, chsh, chfn, gpasswd and the GNOME account "
                             "settings without the master password."))
_register(Action("polkit_admin", "Block Graphical Administrator Prompts", "enforcement",
                 default=False, prompt_verb="perform an administrative task",
                 description="Denies polkit mediated administrator actions (Software "
                             "installers, printer and network changes, GNOME settings)."))
_register(Action("package_management", "Block Package Installation and Removal", "enforcement",
                 default=False, prompt_verb="change installed software"))
_register(Action("removable_media", "Block Removable Media Operations", "enforcement",
                 default=False, prompt_verb="change removable media settings"))
_register(Action("root_login", "Block Root Login", "enforcement", default=True, bypass=False,
                 prompt_verb="log in as root",
                 description="Blocks logging in as the root account on consoles and the "
                             "display manager. This cannot be overridden with the master "
                             "password."))
_register(Action("app_control", "Application Control", "applications", default=False,
                 prompt_verb="run this application"))


def action(key: str) -> Action:
    try:
        return ACTIONS[key]
    except KeyError as exc:  # pragma: no cover - programming error
        raise KeyError(f"unknown action {key!r}") from exc


def actions(group: str | None = None) -> list[Action]:
    items = list(ACTIONS.values())
    if group is not None:
        items = [item for item in items if item.group == group]
    return items


# ---------------------------------------------------------------------------
# defaults
# ---------------------------------------------------------------------------

DEFAULT_POLICY: dict[str, Any] = {
    "schema": SCHEMA,
    "enabled": True,
    "install": {
        "id": "",
        "installed_at": "",
        "installed_by": "",
        "installed_version": "",
        "instance_id": "",
    },
    "actions": {key: spec.default for key, spec in ACTIONS.items()},
    "power_button": "require_master",
    "enforcement": {
        "terminal_max_attempts": 3,
        "audit_attempts": True,
        "notify": True,
        "terminal_prompt_text": "Please Enter the Master Password:",
        "terminal_prompt_prefix": "[Sudaeon]",
        "lock_gnome_settings": True,
        "fail_closed": True,
        "prompt_timeout_seconds": 120,
        "lockout_seconds": 30,
    },
    "schedule": {
        "mode": ENFORCE_ALWAYS,
        "windows": [],
    },
    "users": {
        "roles": {},
        "default_role": ROLE_REGULAR,
        "auto_admin_sudo_group": True,
        "exempt_admins": False,
        "ask_master_on_login": False,
    },
    "applications": {
        "enabled": False,
        "blocked": [],
    },
    "advanced": {
        "master_kdf": {"kdf": "scrypt", "n": 32768, "r": 8, "p": 1, "dklen": 32},
        "unlock_minutes": 5,
        "show_policy_user_count": True,
        "banner": "",
    },
}


def default_policy() -> dict[str, Any]:
    return copy.deepcopy(DEFAULT_POLICY)


# ---------------------------------------------------------------------------
# validation / normalisation
# ---------------------------------------------------------------------------

def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on", "allow", "allowed", "enabled"}:
            return True
        if lowered in {"0", "false", "no", "off", "deny", "blocked", "disabled"}:
            return False
    return default


def _as_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def _as_str(value: Any, default: str, maxlen: int = 200) -> str:
    if not isinstance(value, str):
        return default
    text = value.strip()
    if len(text) > maxlen:
        text = text[:maxlen]
    return text or default


def normalize_policy(raw: Any) -> dict[str, Any]:
    """Return a fully populated, validated policy.

    Unknown keys are dropped and out of range values are clamped, so a
    hand-edited or corrupted file can never make the engine crash or become
    stricter than the operator asked for in an unpredictable way.
    """
    policy = default_policy()
    if not isinstance(raw, dict):
        return policy

    policy["enabled"] = _as_bool(raw.get("enabled"), policy["enabled"])
    try:
        policy["schema"] = int(raw.get("schema", SCHEMA))
    except (TypeError, ValueError):
        policy["schema"] = SCHEMA

    install = raw.get("install")
    if isinstance(install, dict):
        for key in policy["install"]:
            if key in install and isinstance(install[key], str):
                policy["install"][key] = install[key]

    actions = raw.get("actions")
    if isinstance(actions, dict):
        for key, spec in ACTIONS.items():
            if key in actions:
                policy["actions"][key] = _as_bool(actions[key], spec.default)

    mode = raw.get("power_button")
    if mode in POWER_BUTTON_MODES:
        policy["power_button"] = mode

    enforcement = raw.get("enforcement")
    if isinstance(enforcement, dict):
        target = policy["enforcement"]
        target["terminal_max_attempts"] = _as_int(
            enforcement.get("terminal_max_attempts"), 3, 1, 10)
        target["audit_attempts"] = _as_bool(enforcement.get("audit_attempts"), True)
        target["notify"] = _as_bool(enforcement.get("notify"), True)
        target["lock_gnome_settings"] = _as_bool(enforcement.get("lock_gnome_settings"), True)
        target["fail_closed"] = _as_bool(enforcement.get("fail_closed"), True)
        target["prompt_timeout_seconds"] = _as_int(
            enforcement.get("prompt_timeout_seconds"), 120, 15, 900)
        target["lockout_seconds"] = _as_int(enforcement.get("lockout_seconds"), 30, 0, 3600)
        target["terminal_prompt_text"] = _as_str(
            enforcement.get("terminal_prompt_text"), "Please Enter the Master Password:", 120)
        target["terminal_prompt_prefix"] = _as_str(
            enforcement.get("terminal_prompt_prefix"), "[Sudaeon]", 40)

    policy["schedule"] = schedule_mod.normalize(raw.get("schedule"))

    users = raw.get("users")
    if isinstance(users, dict):
        target = policy["users"]
        roles = users.get("roles")
        if isinstance(roles, dict):
            for name, role in roles.items():
                # "root" always resolves to the root role, and the C renderer
                # skips accounts whose name cannot be written to a config file
                if _usable_username(name) and role in ROLES:
                    target["roles"][name] = role
        if users.get("default_role") in ROLES:
            target["default_role"] = users["default_role"]
        target["auto_admin_sudo_group"] = _as_bool(users.get("auto_admin_sudo_group"), True)
        target["exempt_admins"] = _as_bool(users.get("exempt_admins"), False)
        target["ask_master_on_login"] = _as_bool(users.get("ask_master_on_login"), False)

    applications = raw.get("applications")
    if isinstance(applications, dict):
        target = policy["applications"]
        target["enabled"] = _as_bool(applications.get("enabled"), False)
        blocked = []
        for entry in applications.get("blocked") or []:
            if not isinstance(entry, dict):
                continue
            app_id = _as_str(entry.get("id"), "", 120)
            if not app_id or not re.fullmatch(r"[A-Za-z0-9._+-]{1,120}", app_id):
                continue
            blocked.append({
                "id": app_id,
                "name": _as_str(entry.get("name"), app_id, 120),
                "exec": _as_str(entry.get("exec"), "", 300),
                "icon": _as_str(entry.get("icon"), "", 120),
                "path": _as_str(entry.get("path"), "", 300),
                "added": _as_str(entry.get("added"), "", 40),
            })
        # de-duplicate by id, keep first
        seen = set()
        target["blocked"] = [item for item in blocked
                             if not (item["id"] in seen or seen.add(item["id"]))]

    advanced = raw.get("advanced")
    if isinstance(advanced, dict):
        target = policy["advanced"]
        target["unlock_minutes"] = _as_int(advanced.get("unlock_minutes"), 5, 0, 60)
        target["show_policy_user_count"] = _as_bool(advanced.get("show_policy_user_count"), True)
        target["banner"] = _as_str(advanced.get("banner"), "", 300)
        kdf = advanced.get("master_kdf")
        if isinstance(kdf, dict):
            from . import crypto
            try:
                target["master_kdf"] = crypto.check_kdf(kdf)
            except ValueError:
                pass

    return policy


def validate_policy(policy: dict[str, Any]) -> list[str]:
    """Return a list of human readable problems (empty when the policy is fine)."""
    problems: list[str] = []
    if not isinstance(policy, dict):
        return ["Policy is not an object."]
    if policy.get("schema") != SCHEMA:
        problems.append(f"Unknown policy schema: {policy.get('schema')!r}")
    if policy.get("power_button") not in POWER_BUTTON_MODES:
        problems.append("Invalid power button mode.")
    problems.extend(schedule_mod.validate(policy.get("schedule")))
    for name, role in (policy.get("users", {}).get("roles") or {}).items():
        if role not in ROLES:
            problems.append(f"User {name!r} has an invalid role {role!r}.")
    blocked = policy.get("applications", {}).get("blocked") or []
    if not isinstance(blocked, list):
        problems.append("Application list is malformed.")
    return problems


# ---------------------------------------------------------------------------
# accessors
# ---------------------------------------------------------------------------

def action_allowed(policy: dict[str, Any], key: str) -> bool:
    return bool(policy.get("actions", {}).get(key, ACTIONS[key].default))


def set_action(policy: dict[str, Any], key: str, value: bool) -> None:
    policy.setdefault("actions", {})[key] = bool(value)


def role_for(policy: dict[str, Any], username: str) -> str:
    """Resolve the effective role of ``username``."""
    if username == "root":
        return "root"
    users = policy.get("users", {})
    roles = users.get("roles") or {}
    explicit = roles.get(username)
    if explicit in ROLES:
        return explicit
    if users.get("auto_admin_sudo_group", True) and is_admin_user(username):
        return ROLE_ADMIN
    return users.get("default_role", ROLE_REGULAR)


def set_role(policy: dict[str, Any], username: str, role: str) -> None:
    if role not in ROLES:
        raise ValueError(f"invalid role: {role!r}")
    policy.setdefault("users", {}).setdefault("roles", {})[username] = role


def is_subject(policy: dict[str, Any], username: str) -> bool:
    """True when policy applies to ``username``."""
    role = role_for(policy, username)
    if role == "root":
        return False
    if role == ROLE_EXEMPT:
        return False
    if role == ROLE_ADMIN and policy.get("users", {}).get("exempt_admins"):
        return False
    return True


def can_open_dashboard(policy: dict[str, Any], username: str) -> bool:
    return role_for(policy, username) == ROLE_ADMIN


def enforcement_active(policy: dict[str, Any], when=None) -> bool:
    """Whether policy is being enforced right now."""
    if not policy.get("enabled"):
        return False
    return schedule_mod.active_now(policy.get("schedule"), when)


def blocked_applications(policy: dict[str, Any]) -> list[dict[str, Any]]:
    if not policy.get("applications", {}).get("enabled"):
        return []
    return list(policy.get("applications", {}).get("blocked") or [])


def blocked_app(policy: dict[str, Any], app_id: str) -> dict[str, Any] | None:
    for entry in blocked_applications(policy):
        if entry.get("id") == app_id:
            return entry
    return None


def stamp_policy(policy: dict[str, Any]) -> dict[str, Any]:
    policy["updated_at"] = now_iso()
    return policy


# ---------------------------------------------------------------------------
# rendering for the C PAM module / helper
# ---------------------------------------------------------------------------

def render_enforcement_conf(policy: dict[str, Any], *, usernames: Iterable[str] = (),
                            verifier_path: str = "/var/lib/sudaeon/master.verifier",
                            recovery_path: str = "/var/lib/sudaeon/recovery.verifier",
                            chkpwd_path: str = "/usr/lib/sudaeon/sudaeon-chkpwd") -> str:
    """Render the flat configuration file read by ``pam_sudaeon.so``.

    Format (line based, ``#`` comments):

        schema=1
        enabled=1
        prompt_timeout=120
        default_require=1
        [action:sudo]
        blocked=1
        require_master=1
        [user:alice]
        role=admin
        exempt=0
        [user:*]
        role=regular
        exempt=0
        [schedule]
        mode=always
        window=Mon,Tue,Wed,Thu,Fri,21:00,07:00

    The window line is shared with the C parser (``sd_config_load``): day names
    or numbers, comma separated, then the start and the end time.  Day names
    are used so the file stays readable for a human reader.
    """
    enforcement = policy.get("enforcement", {})
    active = enforcement_active(policy)
    lines: list[str] = [
        "# Sudaeon enforcement configuration - generated file, do not edit.",
        f"# generated={now_iso()}",
        f"schema={SCHEMA}",
        f"enabled={'1' if policy.get('enabled') else '0'}",
        f"enforcing_now={'1' if active else '0'}",
        f"fail_closed={'1' if enforcement.get('fail_closed', True) else '0'}",
        f"audit={'1' if enforcement.get('audit_attempts', True) else '0'}",
        f"max_attempts={int(enforcement.get('terminal_max_attempts', 3))}",
        f"prompt_timeout={int(enforcement.get('prompt_timeout_seconds', 120))}",
        f"lockout_seconds={int(enforcement.get('lockout_seconds', 30))}",
        f"prompt_prefix={_conf_value(enforcement.get('terminal_prompt_prefix', '[Sudaeon]'))}",
        f"prompt_text={_conf_value(enforcement.get('terminal_prompt_text', 'Please Enter the Master Password:'))}",
        f"chkpwd={chkpwd_path}",
        f"verifier={verifier_path}",
        f"recovery_verifier={recovery_path}",
        f"power_button={policy.get('power_button', 'require_master')}",
        # Actions that are not listed below are unknown to this version of
        # Sudaeon; asking for the master password is the fail closed answer.
        "default_require=1",
        "",
    ]

    lines.append("[schedule]")
    lines.append(f"mode={schedule_mod.mode_of(policy.get('schedule'))}")
    for window in schedule_mod.windows_of(policy.get("schedule")):
        days = ",".join(DAY_NAMES[day] for day in window["days"] if 0 <= day <= 6)
        lines.append(f"window={days},{window['start']},{window['end']}")
    lines.append("")

    for key, spec in ACTIONS.items():
        if spec.group in {"session", "applications"} and not spec.dconf:
            continue
        allowed = action_allowed(policy, key)
        lines.append(f"[action:{key}]")
        lines.append(f"blocked={'0' if allowed else '1'}")
        lines.append(f"require_master={'1' if (not allowed and spec.bypass) else '0'}")
        lines.append(f"bypass={'1' if spec.bypass else '0'}")
        lines.append("")

    default_role = policy.get("users", {}).get("default_role", ROLE_REGULAR)
    for name in sorted(set(usernames) | set((policy.get("users", {}).get("roles") or {}).keys())):
        if not _usable_username(name):
            continue
        role = role_for(policy, name)
        lines.append(f"[user:{name}]")
        lines.append(f"role={role}")
        lines.append(f"exempt={'0' if is_subject(policy, name) else '1'}")
        lines.append("")

    lines.append("[user:*]")
    lines.append(f"role={default_role}")
    lines.append(f"exempt={'0' if default_role != ROLE_EXEMPT else '1'}")
    lines.append("")
    # the global defaults are what C falls back to when the [user:*] section is
    # missing (an older file written by hand, for example)
    lines.append(f"default_role={default_role}")
    lines.append(f"default_exempt={'1' if default_role == ROLE_EXEMPT else '0'}")
    lines.append("")

    apps = blocked_applications(policy)
    for entry in apps:
        if "=" in entry["id"] or "\n" in entry["id"]:
            continue
        lines.append(f"[app:{entry['id']}]")
        lines.append("blocked=1")
        lines.append("")

    return "\n".join(lines) + "\n"


def _usable_username(name: Any) -> bool:
    """Can this account name be written to a line based config file?"""
    if not isinstance(name, str) or not name or name == "root":
        return False
    return not any(character in name for character in (":", "=", "\n", "\r", "#"))


def _conf_value(value: Any) -> str:
    text = str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    return text.strip()[:200]


def summary(policy: dict[str, Any]) -> str:
    """One line summary used in the dashboard and by ``sudaeon status``."""
    if not policy.get("enabled"):
        return "Sudaeon is OFF - no policy is enforced."
    when = schedule_mod.describe(policy.get("schedule"))
    blocked_power = [spec.label.replace("Allow ", "").lower()
                     for spec in actions() if spec.group == "power"
                     and not action_allowed(policy, spec.key)]
    parts = [f"Enforcement is on {when}."]
    if blocked_power:
        parts.append("Blocked: " + ", ".join(blocked_power) + ".")
    if not action_allowed(policy, "sudo"):
        parts.append("Terminal sudo requires the master password.")
    return " ".join(parts)
