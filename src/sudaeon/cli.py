"""The ``sudaeon`` command.

The installed ``/usr/bin/sudaeon`` is a small python shim that imports this
module.  When it is reached through one of its symlinks (``sudaeon-helper``,
``sudaeon-sentinel``, ``sudaeon-polkit-guard``) the corresponding privileged
entry point is used instead, so polkit and sudoers only ever name one file.

Every command that needs root either runs directly (when the caller already is
root, which is what ``sudo sudaeon`` does) or goes through the privileged
helper; the master password always travels on stdin, never in argv.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from . import config, installstate, paths, privilege, vault
from .util import invoking_uid, username_of
from .version import APP_VERSION

USAGE = f"""Sudaeon {APP_VERSION} - parental controls for Ubuntu 24.04 LTS

usage: sudaeon [COMMAND] [options]

Without a command the dashboard is opened (Administrators only; run
"sudo sudaeon" when your account is not a Sudaeon Administrator yet).

Everyday commands
  setup                     create the master password (first run)
  dashboard [--page NAME]   open the dashboard: power, enforcement, users,
                            schedule, applications, logs, advanced
  status                    show whether Sudaeon is enforcing anything
  users                     list the accounts and their roles
  audit [-n N]              show the newest audit entries
  doctor                    check PAM, polkit, sudoers, dconf and the service
  permission [--verb TEXT]  ask for the master password (used by scripts)
  app-launch ID [-- ARG…]   start a blocked application after the prompt
  version                   print the version

Administrator commands (sudo, or the master password)
  install [--force]         install Sudaeon system wide
  apply                     rewrite every enforcement file from the policy
  repair                    rebuild the verifier and the enforcement files
  reset-password            set a new master password (recovery key or root)
  change-password           change the master password
  recovery                  show the recovery key
  sentinel [status|reload]  control the background service
  power ACTION              reboot, poweroff, suspend, … through Sudaeon
  uninstall [--purge]       remove Sudaeon (and its state with --purge)
  update [--check]          check for / install a newer release

Options
  -n, --lines N             audit entries to show (default 20)
  -v, --verb TEXT           what the permission prompt is asking for
  --json                    machine readable output where supported
  -h, --help                this text
"""

POWER_ACTIONS = ("reboot", "poweroff", "halt", "suspend", "hibernate",
                 "hybrid_sleep", "suspend_then_hibernate", "kexec", "soft_reboot")


# ---------------------------------------------------------------------------
# small output helpers
# ---------------------------------------------------------------------------

def _print(message: str = "") -> None:
    print(message)


def _fail(message: str, code: int = 1) -> int:
    print(f"Sudaeon: {message}", file=sys.stderr)
    return code


def _root() -> bool:
    return os.geteuid() == 0


def _display() -> bool:
    return bool(os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY"))


def _gui_available() -> bool:
    from .gui import gui_available

    return gui_available()


def _ask_master(verb: str) -> str:
    """Ask for the master password on the terminal (3 strikes, then refuse)."""
    from . import prompt

    result = prompt.terminal_ask(verb)
    return result.password if result.ok else ""


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_setup(argv: list[str]) -> int:
    from .gui import gui_available

    if installstate.is_installed() and vault.read_master_record() is not None:
        return report_already_installed()
    if not _display() or not gui_available():
        return _fail("the setup wizard needs a desktop session (or run "
                     "'sudo sudaeon install --master-password' from a terminal)", 3)
    from .gui.app import SetupWizard

    return SetupWizard().run()


def report_already_installed() -> int:
    """The duplicate-install popup, with a terminal fallback."""
    from .installer import ALREADY_INSTALLED_MESSAGE

    if _display() and _gui_available():
        from .gui.app import already_installed

        already_installed()
    print(ALREADY_INSTALLED_MESSAGE, file=sys.stderr)
    detail = installstate.find_conflict()
    if detail:
        print(f"  {detail}", file=sys.stderr)
    return 1


def cmd_dashboard(argv: list[str]) -> int:
    page = _option(argv, "--page", "")
    if not installstate.is_installed() or vault.read_master_record() is None:
        return cmd_setup(argv)
    if not _display() or not _gui_available():
        allowed, reason = privilege.dashboard_entry_allowed()
        if not allowed:
            return _fail(reason, 5)
        from . import diagnostics

        _print(diagnostics.format_report(diagnostics.run_checks()))
        return 0
    from .gui.app import run_dashboard

    return run_dashboard(page)


def cmd_status(_argv: list[str]) -> int:
    policy = vault.load_policy()
    _print(f"Sudaeon {APP_VERSION}")
    if not installstate.is_installed():
        _print("state:       not installed")
        return 0
    _print(f"sudaeon:     {'enabled' if policy and policy.get('enabled') else 'disabled'}")
    if policy:
        summary = config.summary(policy)
        _print(f"policy:      {summary}")
        _print(f"schedule:    {config.schedule_summary(policy)}")
        users = policy.get("users", {})
        roles = users.get("roles") or {}
        _print(f"users:       {len(roles)} with an explicit role, "
               f"default {users.get('default_role', config.ROLE_REGULAR)}")
        blocked = config.blocked_applications(policy)
        _print(f"applications:{len(blocked):4d} blocked")
    for label, path in (("policy", paths.POLICY_FILE),
                        ("verifier", paths.MASTER_VERIFIER),
                        ("vault", paths.VAULT_FILE),
                        ("enforcement", paths.ENFORCEMENT_CONF),
                        ("audit log", paths.AUDIT_LOG)):
        state = "present" if path.exists() else "missing"
        _print(f"{label + ':':<13}{state}  {path}")
    _print(f"sentinel:    {'running' if _sentinel_running() else 'not running'}")
    _print(f"escalation:  {privilege.describe_escalation()}")
    return 0


def cmd_users(_argv: list[str]) -> int:
    from . import users as users_mod

    policy = vault.load_policy() or config.default_policy()
    entries = users_mod.list_users(policy)
    if not entries:
        _print("no accounts found")
        return 0
    _print(f"{'user':<16}{'uid':>6}  {'role':<22}enforcement")
    for entry in entries:
        role = config.role_for(policy, entry["name"])
        subject = "yes" if config.is_subject(policy, entry["name"]) else "no"
        _print(f"{entry['name']:<16}{entry['uid']:>6}  "
               f"{config.ROLE_LABELS.get(role, role):<22}{subject}")
    return 0


def cmd_audit(argv: list[str]) -> int:
    from . import audit

    limit = int(_option(argv, "--lines", "") or _option(argv, "-n", "") or 20)
    entries = audit.read(limit)
    if not entries:
        _print("the audit log is empty")
        return 0
    for entry in entries:
        _print(audit.format_entry(entry))
    return 0


def cmd_doctor(_argv: list[str]) -> int:
    from . import diagnostics

    report = diagnostics.run_checks()
    _print(diagnostics.format_report(report))
    return 0 if report.get("ok", True) else 1


def cmd_permission(argv: list[str]) -> int:
    """Ask for the master password and report the result through the exit code."""
    import json

    from . import prompt

    verb = _option(argv, "--verb", "") or _option(argv, "-v", "")
    result = prompt.request_permission(verb or "complete this action", action="cli")
    if "--json" in argv:
        _print(json.dumps({"ok": result.ok, "reason": result.reason,
                           "attempts": result.attempts}))
    if not result.ok:
        return 2
    return 0


def cmd_app_launch(argv: list[str]) -> int:
    from . import appgate

    if not argv:
        return _fail("no application was given", 4)
    app_id = argv[0]
    extra = argv[argv.index("--") + 1:] if "--" in argv else argv[1:]
    return appgate.launch(app_id, list(extra))


def cmd_apply(argv: list[str]) -> int:
    if _root():
        from . import apply as apply_mod

        policy = vault.load_policy()
        if policy is None:
            return _fail("Sudaeon is not installed", 2)
        report = apply_mod.apply_all(policy)
        for step in report["steps"]:
            _print(f"{'ok ' if step['ok'] else 'err'} {step['step']}: {step['detail']}")
        return 0 if report.get("ok") else 1
    password = _password_option(argv) or _ask_master("apply the Sudaeon policy")
    result = privilege.call_helper_with_master("apply-enforcement", password, {},
                                               timeout=300.0)
    return _helper_result(result)


def cmd_repair(argv: list[str]) -> int:
    password = _password_option(argv) or _ask_master("repair Sudaeon")
    result = privilege.call_helper_with_master("repair", password, {})
    return _helper_result(result)


def cmd_recovery(argv: list[str]) -> int:
    password = _password_option(argv) or _ask_master("show the recovery key")
    result = privilege.call_helper_with_master("show-recovery", password, {})
    if not result.ok:
        return _helper_result(result)
    from . import crypto

    key = str((result.data or {}).get("recovery_key") or "")
    _print(crypto.recovery_key_display(key) or key)
    return 0


def cmd_change_password(argv: list[str]) -> int:
    from . import crypto

    old = _password_option(argv) or _ask_master("change the master password")
    if not old:
        return 1
    new = _prompt_new_password(crypto)
    if not new:
        return 1
    result = privilege.call_helper_with_master("change-master", old, {"new": new})
    if not result.ok:
        return _helper_result(result)
    _print("The master password was changed.")
    return 0


def cmd_reset_password(argv: list[str]) -> int:
    """Reset the master password using the recovery key (terminal fallback)."""
    if _display() and _gui_available():
        from .gui.reset_dialog import ResetPasswordDialog

        state = {"done": False}
        dialog = ResetPasswordDialog(None,
                                     on_done=lambda _pw, _key: state.update(done=True))
        dialog.present()
        return 0 if state["done"] else 1

    from . import crypto

    if installstate.is_installed() and vault.read_master_record() is not None:
        recovery = input("Recovery key (leave empty to use administrator rights): ")
    else:
        recovery = ""
    new = _prompt_new_password(crypto)
    if not new:
        return 1
    payload: dict[str, Any] = {"new": new, "new_password_confirm": new}
    if recovery.strip():
        payload["recovery_key"] = crypto.normalize_recovery_key(recovery.strip())
    else:
        payload["force"] = True
        if not _root():
            return _fail("resetting without the recovery key needs root: "
                         "run 'sudo sudaeon reset-password'", 3)
    result = privilege.call_helper_with_master("reset-master", "", payload)
    if not result.ok:
        return _helper_result(result)
    key = str((result.data or {}).get("recovery_key") or "")
    _print("The master password was reset.")
    if key:
        _print("New recovery key:")
        _print(crypto.recovery_key_display(key) or key)
    return 0


def cmd_install(argv: list[str]) -> int:
    """Install Sudaeon.

    The master password is *deferred* to the setup wizard unless one is given
    with --master-password, so the first run always asks for it twice.
    """
    if installstate.is_installed() and vault.read_master_record() is not None:
        return report_already_installed()
    force = "--force" in argv
    password = _password_option(argv)
    user = username_of(invoking_uid()) or "root"
    payload: dict[str, Any] = {"user": user, "force": force}

    if _root():
        from . import installer

        report = installer.install(invoking_user=user, master_password=password or None,
                                   force=force)
        if report.get("already_installed"):
            return report_already_installed()
        if not report.get("ok"):
            for warning in report.get("warnings") or ["installation failed"]:
                print(f"Sudaeon: {warning}", file=sys.stderr)
            return 1
        _print("Sudaeon is installed.")
        key = str(report.get("recovery_key") or "")
        if key:
            from . import crypto

            _print("Recovery key:")
            _print(crypto.recovery_key_display(key) or key)
        else:
            _print("Run 'sudaeon setup' to create the master password.")
        return 0

    result = privilege.call_helper_with_master("install", password or "", payload,
                                               timeout=900.0)
    if not result.ok and "already installed" in (result.error or "").lower():
        return report_already_installed()
    code = _helper_result(result)
    if code == 0:
        key = str((result.data or {}).get("recovery_key") or "")
        if key:
            from . import crypto

            _print("Recovery key:")
            _print(crypto.recovery_key_display(key) or key)
        else:
            _print("Run 'sudaeon setup' to create the master password.")
    return code


def cmd_uninstall(argv: list[str]) -> int:
    purge = "--purge" in argv
    password = _password_option(argv)
    payload: dict[str, Any] = {"purge": purge}
    if not password:
        password = _ask_master("remove Sudaeon")
        if not password:
            payload["force"] = True
            if not _root():
                return _fail("the master password (or root) is required to remove Sudaeon",
                             3)
    result = privilege.call_helper_with_master("uninstall", password, payload)
    return _helper_result(result)


def cmd_sentinel(argv: list[str]) -> int:
    from . import sentinel

    action = argv[0] if argv else "status"
    if action == "status":
        info = sentinel.status()
        _print(f"sentinel: {'running' if info.get('running') else 'not running'}")
        state = info.get("state") or {}
        for key in ("policy_enabled", "power_button", "last_action", "updated_at"):
            if key in state:
                _print(f"{key + ':':<16}{state[key]}")
        return 0
    if action == "reload":
        if not _root():
            return _fail("reloading the sentinel needs root", 3)
        response = sentinel.control({"kind": "reload"})
        if response is None:
            return _fail("the sentinel is not running", 3)
        _print(response.get("message") or response)
        return 0 if response.get("ok") else 1
    return _fail(f"unknown sentinel command: {action}", 2)


def cmd_power(argv: list[str]) -> int:
    if not argv:
        return _fail("choose one of: " + ", ".join(POWER_ACTIONS), 2)
    action = argv[0]
    if action not in POWER_ACTIONS:
        return _fail(f"unknown power action: {action}", 2)
    from . import sentinel

    if not sentinel.running():
        return _fail("the Sudaeon service is not running; use 'systemctl reboot' "
                     "directly", 3)
    response = sentinel.control({"kind": "perform", "action": action}, timeout=120.0)
    if response is None:
        return _fail("the Sudaeon service did not answer", 3)
    if response.get("ok"):
        _print(f"Sudaeon performed: {action}")
        return 0
    return _fail(str(response.get("error") or "the action was refused"), 1)


def cmd_agent(argv: list[str]) -> int:
    """The per-session helper that shows the permission dialogs.

    It is normally started by the sentinel with an inherited socket, never by
    hand; ``--session`` is accepted for compatibility.
    """
    from .sentinel import agent

    return agent.main([item for item in argv if item != "--session"])


def cmd_update(argv: list[str]) -> int:
    from . import updater

    if "--check" in argv:
        info = updater.check_for_update()
        if not info:
            _print("No update information is available (no network or no release).")
            return 0
        _print(f"installed: {info.get('installed')}  available: {info.get('available')}")
        return 0
    result = updater.install_update()
    return _helper_result(result)


def cmd_version(_argv: list[str]) -> int:
    _print(f"Sudaeon {APP_VERSION}")
    _print(f"state: {paths.STATE_DIR}")
    return 0


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _option(argv: list[str], name: str, default: str) -> str:
    if name in argv:
        index = argv.index(name)
        if index + 1 < len(argv):
            return argv[index + 1]
    prefix = f"{name}="
    for item in argv:
        if item.startswith(prefix):
            return item[len(prefix):]
    return default


def _password_option(argv: list[str]) -> str:
    return _option(argv, "--master-password", "") or _option(argv, "--password", "")


def _prompt_new_password(crypto_mod) -> str:
    first = input("New master password: ")
    second = input("Retype the new master password: ")
    if first != second:
        _fail("the passwords do not match")
        return ""
    problems = crypto_mod.password_problems(first, username=username_of(invoking_uid()) or "")
    if problems:
        _fail(" ".join(problems))
        return ""
    return first


def _helper_result(result: privilege.HelperResult) -> int:
    if result.ok:
        message = result.message or "done"
        _print(message)
        return 0
    return _fail(result.error or "the helper refused the request", 1)


def _sentinel_running() -> bool:
    try:
        from . import sentinel

        return bool(sentinel.running())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

COMMANDS = {
    "setup": cmd_setup,
    "dashboard": cmd_dashboard,
    "status": cmd_status,
    "users": cmd_users,
    "audit": cmd_audit,
    "doctor": cmd_doctor,
    "permission": cmd_permission,
    "app-launch": cmd_app_launch,
    "apply": cmd_apply,
    "repair": cmd_repair,
    "recovery": cmd_recovery,
    "change-password": cmd_change_password,
    "reset-password": cmd_reset_password,
    "install": cmd_install,
    "uninstall": cmd_uninstall,
    "sentinel": cmd_sentinel,
    "power": cmd_power,
    "agent": cmd_agent,
    "update": cmd_update,
    "version": cmd_version,
}


def _dispatch_by_name(program: str, argv: list[str]) -> int | None:
    """The symlink names keep the privileged entry points in one binary."""
    name = Path(program).name
    if name.endswith("sudaeon-helper"):
        from . import helper

        return helper.dispatch(argv)
    if name.endswith("sudaeon-sentinel"):
        from .sentinel import daemon

        return daemon.main(argv)
    if name.endswith("sudaeon-polkit-guard"):
        from . import polkit_guard

        return polkit_guard.main(argv)
    if name.endswith("sudaeon-chkpwd"):
        return _fail("sudaeon-chkpwd is a native program; run the copy in "
                     "/usr/lib/sudaeon", 4)
    return None


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    program = sys.argv[0] if sys.argv else "sudaeon"
    by_name = _dispatch_by_name(program, argv)
    if by_name is not None:
        return by_name

    if argv and argv[0] in ("-h", "--help", "help"):
        _print(USAGE)
        return 0
    if argv and argv[0] in ("--version",):
        return cmd_version(argv)

    verb = ""
    for item in argv:
        if item.startswith("-"):
            continue
        verb = item
        break
    if not verb:
        return cmd_dashboard([])

    command = COMMANDS.get(verb)
    if command is None:
        return _fail(f"unknown command: {verb} (try 'sudaeon --help')", 2)
    rest = [item for item in argv[argv.index(verb) + 1:]]
    return command(rest)


if __name__ == "__main__":  # pragma: no cover - manual entry point
    raise SystemExit(main())
