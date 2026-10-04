"""Rendering and installing the enforcement artifacts.

``apply_all()`` is the only function that touches system configuration.  It is
idempotent, backs up every file it edits (``/var/lib/sudaeon/backup``) and never
writes a file that fails validation first (``visudo -c`` for sudoers).

Artifacts
---------
``/var/lib/sudaeon/enforcement.conf``   flat policy for the PAM module
``/etc/sudoers.d/sudaeon``              admin group + no sudo timestamp caching
``/etc/polkit-1/rules.d/00-sudaeon.rules``  polkit decision hook
``/usr/share/polkit-1/actions/com.sudaeon.policy``  pkexec action for installs
``/etc/pam.d/*``                        module insertion (see pam.py)
``/etc/dconf/db/local.d/98-sudaeon``    GNOME lockdown (only when locking is on)
``/etc/dconf/profile/user``             dconf profile including local db
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from . import config, paths, users
from .util import atomic_write, ensure_dir, log, now_iso, read_text, run, which, write_json

POLKIT_RULES_TEMPLATE = """// Sudaeon enforcement rules - generated file, do not edit.
//
// This file sorts before every other rules file so it is consulted first.
// Each rule asks the Sudaeon polkit guard (running as polkitd) whether the
// action is authorized:
//
//   exit 0  -> authorized by Sudaeon policy (a local administrator allowed it)
//   exit !0 -> not authorized by Sudaeon; fall through to the next decision,
//              which then asks the system's own rules and action defaults.
//
// Blocking actions (shutdown, reboot, user management, ...) are denied for
// policy subjects; the guard simultaneously wakes the Sudaeon sentinel which
// asks for the master password in the active session and completes the action
// itself when the password is correct.

polkit.addRule(function(action, subject) {{
    var managed = [
{prefixes}
    ];
    function isManaged(id) {{
        for (var i = 0; i < managed.length; i++) {{
            if (id.indexOf(managed[i]) === 0) {{
                return true;
            }}
        }}
        return false;
    }}
    if (!isManaged(action.id)) {{
        return undefined;
    }}
    var guard = "{guard}";
    var args = [guard, "authorize", action.id, subject.user,
                subject.session ? subject.session : "",
                subject.active ? "1" : "0",
                subject.local ? "1" : "0"];
    try {{
        polkit.spawn(args);
        return polkit.Result.YES;
    }} catch (error) {{
        // not authorized by Sudaeon: ask it whether it wants to block outright
    }}
    try {{
        polkit.spawn([guard, "deny", action.id, subject.user,
                      subject.session ? subject.session : "",
                      subject.active ? "1" : "0",
                      subject.local ? "1" : "0"]);
        return polkit.Result.NO;
    }} catch (error) {{
        // Sudaeon has no opinion: let polkit's own rules and defaults decide
    }}
    return undefined;
}});
"""

POLKIT_ACTION_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>Sudaeon</vendor>
  <vendor_url>https://github.com/aswartzlander2-sys/sudaeon</vendor_url>
  <icon_name>com.sudaeon.Sudaeon</icon_name>
  <action id="com.sudaeon.manage">
    <description>Install, remove or reconfigure Sudaeon</description>
    <message>Authentication is required to change Sudaeon parental controls</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">{cli}</annotate>
    <annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate>
  </action>
</policyconfig>
"""

SUDOERS_TEMPLATE = """# Managed by Sudaeon - do not edit.  Removed by 'sudaeon uninstall'.
# Members of {group} may run the Sudaeon helper without a password: the helper
# itself demands the master password for every change.
Defaults timestamp_timeout=0
%{group} ALL=(root) NOPASSWD: {helper}
"""

DCONF_LOCK_TEMPLATE = """# Managed by Sudaeon - do not edit.
[org/gnome/desktop/lockdown]
{entries}
"""

DCONF_PROFILE_LINES = ("user-db:user", "system-db:local")


# ---------------------------------------------------------------------------
# low level writers
# ---------------------------------------------------------------------------

def _backup(path: Path, store: Path) -> None:
    if not path.exists():
        return
    try:
        store.mkdir(parents=True, exist_ok=True)
        target = store / path.name.replace("/", "_")
        if not target.exists():
            shutil.copy2(path, target)
    except OSError as exc:  # pragma: no cover - best effort
        log(f"could not back up {path}: {exc}")


def write_enforcement_conf(policy: dict[str, Any]) -> str:
    names = [entry["name"] for entry in users.list_users(policy)]
    text = config.render_enforcement_conf(
        policy,
        usernames=names,
        verifier_path=str(paths.MASTER_VERIFIER),
        recovery_path=str(paths.RECOVERY_VERIFIER),
        chkpwd_path=str(paths.CHKPWD_BIN),
    )
    atomic_write(paths.ENFORCEMENT_CONF, text, mode=0o644)
    return text


def write_sudoers() -> tuple[bool, str]:
    """Install the sudoers drop-in, validating it with visudo first."""
    from .version import ADMIN_GROUP
    body = SUDOERS_TEMPLATE.format(group=ADMIN_GROUP, helper=paths.HELPER_BIN)
    if not which("visudo"):
        return False, "visudo is not available; sudoers was not modified"
    ensure_dir(paths.SUDOERS_DIR, 0o750)
    temp = paths.SUDOERS_DIR / ".sudaeon.check"
    atomic_write(temp, body, mode=0o440)
    proc = run(["visudo", "-c", "-f", str(temp)], timeout=20)
    if proc.returncode != 0:
        try:
            temp.unlink()
        except OSError:
            pass
        return False, (proc.stderr or "").strip() or "visudo rejected the file"
    _backup(paths.SUDOERS_FILE, paths.STATE_DIR / "backup")
    try:
        os.replace(temp, paths.SUDOERS_FILE)
        os.chmod(paths.SUDOERS_FILE, 0o440)
    except OSError as exc:
        return False, f"could not install {paths.SUDOERS_FILE}: {exc}"
    return True, ""


def remove_sudoers() -> None:
    try:
        paths.SUDOERS_FILE.unlink()
    except OSError:
        pass


def write_polkit_rules() -> tuple[bool, str]:
    prefixes = "\n".join(f'        "{prefix}",' for prefix, _key in
                         __import__("sudaeon.engine", fromlist=["engine"]).POLKIT_PREFIXES)
    body = POLKIT_RULES_TEMPLATE.format(prefixes=prefixes.rstrip(","),
                                        guard=paths.POLKIT_GUARD)
    ensure_dir(paths.POLKIT_RULES_DIR, 0o755)
    _backup(paths.POLKIT_RULES_FILE, paths.STATE_DIR / "backup")
    atomic_write(paths.POLKIT_RULES_FILE, body, mode=0o644)
    return True, ""


def remove_polkit_rules() -> None:
    for path in (paths.POLKIT_RULES_FILE,):
        try:
            path.unlink()
        except OSError:
            pass


def write_polkit_action() -> None:
    body = POLKIT_ACTION_TEMPLATE.format(cli=paths.CLI_BIN)
    ensure_dir(paths.POLKIT_ACTIONS_DIR, 0o755)
    atomic_write(paths.POLKIT_ACTION_FILE, body, mode=0o644)


def remove_polkit_action() -> None:
    try:
        paths.POLKIT_ACTION_FILE.unlink()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# GNOME lockdown / dconf
# ---------------------------------------------------------------------------

def dconf_entries(policy: dict[str, Any]) -> list[str]:
    """`key=value` pairs for org.gnome.desktop.lockdown."""
    entries: list[str] = []
    for spec in config.actions():
        if not spec.dconf:
            continue
        allowed = config.action_allowed(policy, spec.key)
        # the lockdown key means "disabled"; allow == false -> disable == true
        value = "false" if allowed else "true"
        entries.append(f"{spec.dconf[1]}={value}")
    return entries


def write_dconf(policy: dict[str, Any]) -> tuple[bool, str]:
    """Lock the GNOME session settings Sudaeon manages (best effort)."""
    if not paths.DCONF_DB_DIR.parent.exists() and not which("dconf"):
        return False, "dconf is not installed; GNOME session options were not applied"
    if not policy.get("enforcement", {}).get("lock_gnome_settings", True):
        remove_dconf()
        return True, ""
    try:
        ensure_dir(paths.DCONF_DB_DIR, 0o755)
        _backup(paths.DCONF_LOCKDOWN, paths.STATE_DIR / "backup")
        body = DCONF_LOCK_TEMPLATE.format(entries="\n".join(dconf_entries(policy)))
        atomic_write(paths.DCONF_LOCKDOWN, body, mode=0o644)

        # make sure /etc/dconf/profile/user includes the local system db
        profile = read_text(paths.DCONF_PROFILE, "")
        lines = [line.strip() for line in profile.splitlines() if line.strip()]
        missing = [line for line in DCONF_PROFILE_LINES if line not in lines]
        if missing:
            if paths.DCONF_PROFILE.exists():
                _backup(paths.DCONF_PROFILE, paths.STATE_DIR / "backup")
            text = "\n".join(lines + missing) + "\n"
            atomic_write(paths.DCONF_PROFILE, text, mode=0o644)
        if which("dconf"):
            run(["dconf", "update"], timeout=30)
        return True, ""
    except OSError as exc:
        return False, f"could not write dconf configuration: {exc}"


def remove_dconf() -> None:
    try:
        paths.DCONF_LOCKDOWN.unlink()
        if which("dconf"):
            run(["dconf", "update"], timeout=30)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# services
# ---------------------------------------------------------------------------

def systemctl(action: str, unit: str = "sudaeon-sentinel.service", *, timeout: float = 30) -> tuple[int, str]:
    if not which("systemctl"):
        return 127, "systemctl is not available"
    proc = run(["systemctl", action, unit], timeout=timeout)
    return proc.returncode, (proc.stderr or proc.stdout or "").strip()


def daemon_reload() -> None:
    if which("systemctl"):
        run(["systemctl", "daemon-reload"], timeout=20)


# ---------------------------------------------------------------------------
# the entry point
# ---------------------------------------------------------------------------

def apply_all(policy: dict[str, Any], *, start_sentinel: bool = True,
              verify: bool = True) -> dict[str, Any]:
    """Write every enforcement artifact.  Returns a report dictionary."""
    from . import pam as pam_mod
    from . import users as users_mod

    report: dict[str, Any] = {"steps": [], "warnings": [], "ok": True,
                              "applied_at": now_iso()}

    def record(name: str, ok: bool, detail: str = "") -> None:
        report["steps"].append({"step": name, "ok": ok, "detail": detail})
        if not ok:
            report["ok"] = False
            if detail:
                report["warnings"].append(f"{name}: {detail}")

    try:
        write_enforcement_conf(policy)
        record("enforcement.conf", True, "policy rendered for the PAM module")
    except OSError as exc:
        record("enforcement.conf", False, str(exc))

    group = users_mod.sync_admin_group(policy)
    if group.get("errors"):
        record("admin group", False, "; ".join(group["errors"]))
    else:
        record("admin group", True,
               f"added {group['added'] or 'nobody'}, removed {group['removed'] or 'nobody'}")

    ok, detail = write_sudoers()
    record("sudoers", ok, detail)

    write_polkit_action()
    ok, detail = write_polkit_rules()
    record("polkit rules", ok, detail)

    ok, detail = write_dconf(policy)
    record("GNOME settings", ok, detail)

    pam_report = pam_mod.apply(policy, enabled=bool(policy.get("enabled", True)))
    for item in pam_report["steps"]:
        record(f"pam:{item['service']}", item["ok"], item["detail"])

    if start_sentinel:
        daemon_reload()
        code, message = systemctl("enable", "sudaeon-sentinel.service")
        record("sentinel enable", code == 0, message)
        if policy.get("enabled"):
            code, message = systemctl("restart", "sudaeon-sentinel.service")
            record("sentinel restart", code == 0, message)
        else:
            code, message = systemctl("stop", "sudaeon-sentinel.service")
            record("sentinel stop", code == 0, message)

    if verify:
        errors = config.validate_policy(policy)
        if errors:
            record("policy validation", False, "; ".join(errors))
        else:
            record("policy validation", True)

    return report


def uninstall_artifacts(purge: bool = False, *, remove_program: bool = True) -> dict[str, Any]:
    """Remove everything Sudaeon installed outside of /var/lib/sudaeon.

    With ``remove_program=False`` the files that belong to the debian package
    (the launcher, the library directory, the desktop entry, the unit file and
    the icons) are left alone: dpkg removes those itself.
    """
    from . import pam as pam_mod
    report: dict[str, Any] = {"steps": [], "warnings": [], "ok": True}

    def record(name: str, ok: bool, detail: str = "") -> None:
        report["steps"].append({"step": name, "ok": ok, "detail": detail})
        if not ok and detail:
            report["warnings"].append(f"{name}: {detail}")

    code, message = systemctl("stop", "sudaeon-sentinel.service")
    record("sentinel stop", code == 0 or "not loaded" in message.lower(), message)
    systemctl("disable", "sudaeon-sentinel.service")

    pam_report = pam_mod.revert()
    for item in pam_report["steps"]:
        record(f"pam:{item['service']}", item["ok"], item["detail"])

    remove_sudoers()
    record("sudoers", True, "removed")
    remove_polkit_rules()
    remove_polkit_action()
    record("polkit", True, "removed")

    try:
        remove_dconf()
        record("GNOME settings", True, "unlocked")
    except OSError as exc:
        record("GNOME settings", False, str(exc))

    if remove_program:
        for path in (paths.SYSTEMD_SENTINEL_UNIT, paths.DESKTOP_MANAGER,
                     paths.DESKTOP_AGENT, paths.DESKTOP_SETUP, paths.LOGROTATE_FILE,
                     paths.APPS_DIR / f"{paths.APP_ID}.desktop"):
            try:
                path.unlink()
            except OSError:
                pass
        record("files", True, "unit files and desktop entries removed")

    if remove_program:
        for path in (paths.BIN_DIR / "sudaeon",):
            try:
                if path.is_symlink() or path.exists():
                    path.unlink()
            except OSError as exc:
                record("cli", False, str(exc))

    if remove_program:
        try:
            if paths.LIB_DIR.exists():
                shutil.rmtree(paths.LIB_DIR)
            record("library", True, "removed")
        except OSError as exc:
            record("library", False, str(exc))

    for candidate in [directory / paths.PAM_MODULE_NAME
                      for directory in paths.PAM_SECURITY_DIRS] + [paths.PAM_MODULE_SOURCE]:
        try:
            candidate.unlink()
        except OSError:
            pass

    if remove_program:
        for icon in paths.ICON_ROOT.glob("*/apps/com.sudaeon.*"):
            try:
                icon.unlink()
            except OSError:
                pass
        if which("gtk-update-icon-cache") and paths.ICON_ROOT.exists():
            run(["gtk-update-icon-cache", "-q", "-t", "-f", str(paths.ICON_ROOT)],
                timeout=30)
    if which("update-desktop-database"):
        run(["update-desktop-database", "-q", str(paths.APPS_DIR)], timeout=30)

    report["purge"] = purge
    return report
