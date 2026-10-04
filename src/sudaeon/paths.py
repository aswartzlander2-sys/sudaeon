"""Every path Sudaeon uses, in one place.

The module also supports a *sandbox root*: when ``SUDAEON_ROOT`` points at a
directory and the process is not a setuid helper, every path below is resolved
inside that directory instead of ``/``.  That is what lets the test-suite and
``tools/demo.sh`` exercise the real code without touching the host system.

The override is deliberately ignored by setuid processes (``sudaeon-chkpwd``)
and whenever ``SUDAEON_NO_SANDBOX`` is set, so a user cannot point the
installed program at a directory of their own.
"""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "Sudaeon"
APP_ID = "com.sudaeon.Sudaeon"
PROMPT_APP_ID = "com.sudaeon.Permission"
SETUP_APP_ID = "com.sudaeon.Setup"


def _sandbox_root() -> Path | None:
    value = os.environ.get("SUDAEON_ROOT")
    if not value:
        return None
    if os.environ.get("SUDAEON_NO_SANDBOX"):
        return None
    if os.geteuid() == 0 and os.geteuid() != os.getuid():
        return None            # setuid helper: the real system only
    return Path(value)


ROOT: Path | None = _sandbox_root()
SANDBOXED = ROOT is not None


def P(path: str | Path) -> Path:
    """Resolve an absolute system path, honouring the sandbox root."""
    path = Path(path)
    if ROOT is None:
        return path
    return ROOT / str(path).lstrip("/")


# ---------------------------------------------------------------------------
# program files
# ---------------------------------------------------------------------------

LIB_DIR = P("/usr/lib/sudaeon")
PACKAGE_DIR = LIB_DIR / "sudaeon"
CLI_BIN = P("/usr/bin/sudaeon")
HELPER_BIN = LIB_DIR / "sudaeon-helper"
SENTINEL_BIN = LIB_DIR / "sudaeon-sentinel"
GUARD_BIN = LIB_DIR / "sudaeon-polkit-guard"
CHKPWD_BIN = LIB_DIR / "sudaeon-chkpwd"

DOC_DIR = P("/usr/share/doc/sudaeon")
MAN_DIR = P("/usr/share/man/man1")
MANPAGE = MAN_DIR / "sudaeon.1.gz"

PYTHON = "/usr/bin/python3"

#: Where the sources live in a checkout (used by the development helpers).
REPO_ROOT = Path(__file__).resolve().parents[2]
REPO_DIR = REPO_ROOT
SOURCE_ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# desktop integration
# ---------------------------------------------------------------------------

APPLICATIONS_DIR = P("/usr/share/applications")
DESKTOP_FILE = APPLICATIONS_DIR / "com.sudaeon.Sudaeon.desktop"
AUTOSTART_DIR = P("/etc/xdg/autostart")
AGENT_AUTOSTART = AUTOSTART_DIR / "com.sudaeon.Agent.desktop"

ICON_DIR = P("/usr/share/icons/hicolor")
ICON_HICOLOR = ICON_DIR
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256, 512)
ICON_NAME = "com.sudaeon.Sudaeon"
ICON_SYMBOLIC = "com.sudaeon.Sudaeon-symbolic"

LOCAL_BIN = P("/usr/local/bin")
LOCAL_APPLICATIONS = P("/usr/local/share/applications")

# ---------------------------------------------------------------------------
# system integration
# ---------------------------------------------------------------------------

POLKIT_ACTIONS_DIR = P("/usr/share/polkit-1/actions")
POLKIT_ACTION_FILE = POLKIT_ACTIONS_DIR / "com.sudaeon.policy"
POLKIT_RULES_DIR = P("/etc/polkit-1/rules.d")
POLKIT_RULES_FILE = POLKIT_RULES_DIR / "00-sudaeon.rules"

SUDOERS_DIR = P("/etc/sudoers.d")
SUDOERS_FILE = SUDOERS_DIR / "sudaeon"

PAM_DIR = P("/etc/pam.d")
PAM_SERVICES = {
    "sudo": "sudo",
    "su": "su",
    "pkexec": "pkexec",
    "sudo-i": "sudo-i",
    "polkit-1": "polkit-1",
    "passwd": "user_management",
    "chsh": "user_management",
    "chfn": "user_management",
    "gpasswd": "user_management",
    "chpasswd": "user_management",
    "login": "root_login",
    "gdm-password": "root_login",
    "gdm-launch-environment": "root_login",
    "lightdm": "root_login",
    "sddm": "root_login",
    "sshd": "root_login",
}
# PAM loads modules from a directory that depends on the distribution: Ubuntu
# and Debian use /usr/lib/<multiarch>/security, older layouts used /lib/security.
# All of the candidates are probed (inside the sandbox root when one is set).
def _pam_security_dirs() -> tuple[Path, ...]:
    base = P("/")
    found: list[Path] = []
    seen: set[str] = set()
    for pattern in ("usr/lib/*-linux-gnu/security", "usr/lib/security",
                    "lib/*-linux-gnu/security", "lib/security"):
        for candidate in sorted(base.glob(pattern)):
            if not candidate.is_dir():
                continue
            key = str(candidate.resolve())
            if key in seen:
                continue          # /lib is a symlink to /usr/lib on Ubuntu
            seen.add(key)
            found.append(candidate)
    if not found:
        found.append(P("/lib/security"))
    return tuple(found)


PAM_MODULE_NAME = "pam_sudaeon.so"
#: Every directory PAM may load the module from, the preferred one first.
PAM_SECURITY_DIRS = _pam_security_dirs()
#: Where the module is installed so that PAM finds it.
PAM_MODULE = PAM_SECURITY_DIRS[0] / PAM_MODULE_NAME
#: Legacy fallback (usually the same directory).
PAM_MODULE_ALT = PAM_SECURITY_DIRS[-1] / PAM_MODULE_NAME
#: The copy shipped next to the program: the source for repair and for the
#: PAM module directory, exactly like the compiled helper lives in LIB_DIR.
PAM_MODULE_SOURCE = LIB_DIR / PAM_MODULE_NAME
PAM_BACKUP_DIR = P("/var/lib/sudaeon/backup/pam")

DCONF_PROFILE = P("/etc/dconf/profile/user")
DCONF_DB_DIR = P("/etc/dconf/db/local.d")
DCONF_LOCK_DIR = P("/etc/dconf/db/local.d/locks")
DCONF_FILE = DCONF_DB_DIR / "98-sudaeon"
DCONF_LOCK_FILE = DCONF_LOCK_DIR / "98-sudaeon"

SYSTEMD_UNIT_DIR = P("/usr/lib/systemd/system")
TMPFILES_DIR = P("/usr/lib/tmpfiles.d")
TMPFILES_FILE = TMPFILES_DIR / "sudaeon.conf"
SYSTEMD_SENTINEL_UNIT = SYSTEMD_UNIT_DIR / "sudaeon-sentinel.service"
SYSTEMD_USER_UNIT_DIR = P("/usr/lib/systemd/user")
SYSTEMD_AGENT_UNIT = SYSTEMD_USER_UNIT_DIR / "sudaeon-agent.service"

LOGROTATE_FILE = P("/etc/logrotate.d/sudaeon")

# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------

STATE_DIR = P("/var/lib/sudaeon")
BACKUP_DIR = STATE_DIR / "backup"
APP_DIR = STATE_DIR / "appcontrol"          # alias of APPGATE_DIR below

POLICY_FILE = STATE_DIR / "policy.json"
POLICY_BAK = STATE_DIR / "policy.json.bak"
MASTER_VERIFIER = STATE_DIR / "master.verifier"
RECOVERY_VERIFIER = STATE_DIR / "recovery.verifier"
VAULT_FILE = STATE_DIR / "vault.enc"
ENFORCEMENT_CONF = STATE_DIR / "enforcement.conf"
INSTALL_MARKER = STATE_DIR / "installed.json"
LOCKOUT_FILE = STATE_DIR / "lockout.json"

LOG_DIR = P("/var/log/sudaeon")
AUDIT_LOG = LOG_DIR / "audit.log"

RUNTIME_DIR = P("/run/sudaeon")
CONTROL_SOCKET = RUNTIME_DIR / "control.sock"
AGENT_SOCKET_DIR = RUNTIME_DIR / "agents"
SENTINEL_PID = RUNTIME_DIR / "sentinel.pid"
SENTINEL_STATE = RUNTIME_DIR / "state.json"

# ---------------------------------------------------------------------------
# compatibility names
#
# Several modules were written against the original layout names.  Rather than
# renaming the whole tree these aliases keep one vocabulary working everywhere.
# ---------------------------------------------------------------------------

ADMIN_GROUP = "sudaeon-admins"
ETC_DIR = P("/etc/sudaeon")
RUN_DIR = RUNTIME_DIR
CACHE_DIR = STATE_DIR / "cache"
BIN_DIR = P("/usr/bin")
APPS_DIR = APPLICATIONS_DIR
ICON_ROOT = ICON_DIR
SENTINEL_SOCKET = RUNTIME_DIR / "sentinel.sock"
APPGATE_DIR = STATE_DIR / "appcontrol"
DCONF_LOCKDOWN = DCONF_LOCK_FILE
AUDIT_LOG_OLD = LOG_DIR / "audit.log.1"
SYSTEMD_SYSTEM_DIR = SYSTEMD_UNIT_DIR
DESKTOP_MANAGER = DESKTOP_FILE
DESKTOP_AGENT = AGENT_AUTOSTART
DESKTOP_SETUP = APPLICATIONS_DIR / "com.sudaeon.Setup.desktop"
POLKIT_GUARD = GUARD_BIN
STAMP_FILE = RUNTIME_DIR / "stamp"
JOURNAL_DIR = CACHE_DIR / "journal"


def pam_module_installed() -> Path | None:
    """The installed PAM module, wherever this system keeps it (or None)."""
    for directory in PAM_SECURITY_DIRS:
        module = directory / PAM_MODULE_NAME
        if module.exists():
            return module
    return None


def sentinel_socket() -> Path:
    return SENTINEL_SOCKET


def appgate_meta(app_id: str) -> Path:
    """Metadata file for one application gate (the id is sanitised)."""
    safe = "".join(character for character in str(app_id)
                   if character.isalnum() or character in "._-")
    return APPGATE_DIR / f"{safe or 'unknown'}.json"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def agent_socket(uid: int) -> Path:
    return AGENT_SOCKET_DIR / f"agent-{int(uid)}.sock"


def as_system_path(path: Path) -> str:
    """Strip the sandbox root, for display."""
    if ROOT is None:
        return str(path)
    try:
        return "/" + str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def describe() -> dict[str, str]:
    return {
        "lib": str(LIB_DIR),
        "cli": str(CLI_BIN),
        "state": str(STATE_DIR),
        "runtime": str(RUNTIME_DIR),
        "log": str(AUDIT_LOG),
        "policy": str(POLICY_FILE),
        "vault": str(VAULT_FILE),
        "sandbox": str(ROOT) if ROOT else "",
    }
