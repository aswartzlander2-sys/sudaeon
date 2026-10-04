"""Installation and removal of Sudaeon on the computer.

Sudaeon is installed **once per computer**, never per user account: the policy,
the master password and the enforcement hooks live in system directories that
every account shares.  ``install()`` refuses to run twice and reports the
``Sudaeon is already installed on your system`` condition, which the dashboard
turns into the dialog required by the specification.
"""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import Any

from . import (apply as apply_mod, audit, brand, config, installstate, pam as pam_mod,
               paths, vault)
from .util import (ensure_dir, log, now_iso, read_text, run, username_of, which, write_json)
from .version import APP_VERSION, ADMIN_GROUP

ALREADY_INSTALLED_MESSAGE = "Sudaeon is already installed on your system"

LAYOUT: tuple[tuple[Path, int], ...] = (
    (paths.STATE_DIR, 0o755),
    (paths.LOG_DIR, 0o750),
    (paths.RUN_DIR, 0o755),
    (paths.CACHE_DIR, 0o755),
    (paths.ETC_DIR, 0o755),
    (paths.APPGATE_DIR, 0o755),
    (paths.STATE_DIR / "backup", 0o700),
    (paths.STATE_DIR / "users", 0o755),
)

CLI_SHIM = '''#!/usr/bin/python3
"""Sudaeon launcher.

The real program lives in /usr/lib/sudaeon.  When this script is invoked
through one of its symlinks (sudaeon-helper, sudaeon-sentinel,
sudaeon-polkit-guard) the corresponding internal command is used, which keeps
the privileged entry points inside polkit/sudo rules on a single file.
"""

import os
import sys

sys.path.insert(0, "/usr/lib/sudaeon")

try:
    from sudaeon.cli import main
except ImportError as exc:  # pragma: no cover - installation problem
    print(f"Sudaeon is not installed correctly: {exc}", file=sys.stderr)
    print("Reinstall it with 'sudo apt install --reinstall sudaeon' or run "
          "'sudo make install' from the source tree.", file=sys.stderr)
    raise SystemExit(3)

if __name__ == "__main__":
    raise SystemExit(main())
'''

README_ETC = """Sudaeon - parental controls for Ubuntu
=====================================

This directory only holds a short pointer; the program keeps its state in
/var/lib/sudaeon and its audit log in /var/log/sudaeon.

  sudaeon                     open the dashboard (administrators only)
  sudaeon status              show enforcement status
  sudaeon doctor              diagnose problems
  sudo sudaeon repair         rewrite every enforcement file from the policy
  sudo sudaeon reset-password reset the master password (recovery key or root)
  sudaeon --help              all commands

Configuration is not edited by hand: use the dashboard, or
'python3 -m sudaeon.cli apply' after editing /var/lib/sudaeon/policy.json.
"""


def _copy_if_needed(source: Path, target: Path, mode: int = 0o644) -> bool:
    try:
        if target.exists() and source.is_file() and target.read_bytes() == source.read_bytes():
            return False
    except OSError:
        pass
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        shutil.copytree(source, target, dirs_exist_ok=True)
    else:
        shutil.copy2(source, target)
    try:
        os.chmod(target, mode)
    except OSError:
        pass
    return True


def install_system_files(*, from_package: bool = False) -> list[str]:
    """Place the program files.  Idempotent; safe after a dpkg install."""
    steps: list[str] = []
    pkg_source = paths.PACKAGE_DIR
    lib_pkg = paths.LIB_DIR / "sudaeon"

    if not from_package:
        ensure_dir(paths.LIB_DIR, 0o755)
        try:
            shutil.copytree(pkg_source, lib_pkg, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            steps.append(f"python package -> {lib_pkg}")
        except OSError as exc:
            log(f"could not install the python package: {exc}")

    # launcher and its symlinks
    shim = paths.CLI_BIN
    try:
        ensure_dir(shim.parent, 0o755)
        shim.write_text(CLI_SHIM, encoding="utf-8")
        os.chmod(shim, 0o755)
        steps.append(f"launcher -> {shim}")
    except OSError as exc:
        log(f"could not write {shim}: {exc}")
    for name in ("sudaeon-helper", "sudaeon-sentinel", "sudaeon-polkit-guard"):
        link = paths.LIB_DIR / name
        try:
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(paths.CLI_BIN)
            steps.append(f"symlink -> {link}")
        except OSError as exc:
            log(f"could not create {link}: {exc}")

    # compiled helpers
    for source, target, mode in (
        (paths.REPO_DIR / "build" / "sudaeon-chkpwd", paths.CHKPWD_BIN, 0o4755),
        (paths.REPO_DIR / "build" / "pam_sudaeon.so", paths.PAM_MODULE, 0o644),
    ):
        if source.exists():
            try:
                _copy_if_needed(source, target, mode)
                os.chmod(target, mode)
                steps.append(f"{source.name} -> {target} ({oct(mode)})")
            except OSError as exc:
                log(f"could not install {source}: {exc}")
        elif not from_package:
            log(f"warning: {source} has not been built")

    # desktop entries, unit files, icons, docs
    try:
        ensure_dir(paths.APPS_DIR, 0o755)
        (paths.APPS_DIR / f"{config_icon_id()}.desktop").write_text(
            brand.desktop_entry(f"{paths.CLI_BIN}"), encoding="utf-8")
        os.chmod(paths.APPS_DIR / f"{config_icon_id()}.desktop", 0o644)
        steps.append("desktop entry")
        ensure_dir(paths.AUTOSTART_DIR, 0o755)
        (paths.AUTOSTART_DIR / "com.sudaeon.Permission.agent.desktop").write_text(
            brand.agent_autostart_entry(), encoding="utf-8")
        ensure_dir(paths.SYSTEMD_SYSTEM_DIR, 0o755)
        (paths.SYSTEMD_SYSTEM_DIR / "sudaeon-sentinel.service").write_text(
            brand.systemd_unit(), encoding="utf-8")
        ensure_dir(paths.LOGROTATE_FILE.parent, 0o755)
        paths.LOGROTATE_FILE.write_text(brand.logrotate_config(), encoding="utf-8")
        journal = paths.CACHE_DIR / "journal"
        ensure_dir(journal, 0o755)
        steps.append("unit files and autostart entry")
    except OSError as exc:
        log(f"could not install system files: {exc}")

    icons = brand.build_icons(verbose=False)
    if icons.get("rendered"):
        steps.append(f"{len(icons['rendered'])} icons")
    elif icons.get("failed"):
        log(f"warning: could not render icons {icons['failed']}")

    try:
        ensure_dir(paths.ETC_DIR, 0o755)
        (paths.ETC_DIR / "README").write_text(README_ETC, encoding="utf-8")
        steps.append("documentation")
    except OSError:
        pass

    if which("update-desktop-database"):
        run(["update-desktop-database", "-q", str(paths.APPS_DIR)], timeout=30)
    return steps


def config_icon_id() -> str:
    from .version import APP_ID
    return APP_ID


def create_layout() -> list[str]:
    created: list[str] = []
    for path, mode in LAYOUT:
        try:
            ensure_dir(path, mode)
            os.chmod(path, mode)
            created.append(str(path))
        except OSError as exc:
            log(f"could not create {path}: {exc}")
    return created


def install(*, invoking_user: str = "", master_password: str | None = None,
            force: bool = False, from_package: bool = False) -> dict[str, Any]:
    """Install Sudaeon system wide.  Must run as root."""
    import os as _os
    report: dict[str, Any] = {"ok": True, "steps": [], "warnings": [], "started": now_iso()}

    def record(name: str, ok: bool, detail: str = "") -> None:
        report["steps"].append({"step": name, "ok": ok, "detail": detail})
        if not ok:
            report["ok"] = False
            if detail:
                report["warnings"].append(f"{name}: {detail}")

    if _os.geteuid() != 0:
        record("privileges", False, "installation requires root")
        return report

    conflict = installstate.find_conflict()
    if conflict and not force:
        report["ok"] = False
        report["already_installed"] = True
        report["conflict"] = conflict
        report["message"] = ALREADY_INSTALLED_MESSAGE
        record("conflict", False, conflict)
        audit.append("install", "deny", user=invoking_user or "?",
                     detail=f"already installed: {conflict}", source="installer")
        return report

    record("layout", True, f"{len(create_layout())} directories")
    for step in install_system_files(from_package=from_package):
        record("files", True, step)

    policy = vault.load_policy() or config.default_policy()
    install_meta = policy.setdefault("install", {})
    install_meta.update({
        "instance_id": installstate.new_instance_id(),
        "installed_at": install_meta.get("installed_at") or now_iso(),
        "installed_by": invoking_user or username_of(os.getuid()) or "root",
        "installed_version": APP_VERSION,
    })
    if invoking_user:
        if invoking_user == "root":
            pass
        else:
            try:
                config.set_role(policy, invoking_user, config.ROLE_ADMIN)
            except ValueError as exc:
                record("admin role", False, str(exc))
    policy["enabled"] = False if master_password is None else True
    config.stamp_policy(policy)

    if master_password:
        result = vault.provision(master_password, policy,
                                 params=policy.get("advanced", {}).get("master_kdf"))
        record("master password", True, "verifier, recovery key and vault created")
        report["recovery_key"] = result["recovery_key"]
    else:
        record("master password", True, "deferred to the setup wizard")

    try:
        vault.save_policy(policy)
        record("policy", True, str(paths.POLICY_FILE))
    except OSError as exc:
        record("policy", False, str(exc))

    installstate.write_marker(policy)
    record("marker", True, str(paths.INSTALL_MARKER))

    applied = apply_mod.apply_all(policy, start_sentinel=True)
    for step in applied["steps"]:
        record(f"apply:{step['step']}", step["ok"], step["detail"])
    report["apply"] = applied

    ot, message = pam_mod.verify()
    record("pam verify", ot, message)

    report["installed_version"] = APP_VERSION
    report["policy"] = policy
    audit.append("install", "change", user=invoking_user or "?",
                 detail=f"installed version {APP_VERSION}", source="installer")
    return report


def uninstall(*, purge: bool = False) -> dict[str, Any]:
    report: dict[str, Any] = {"ok": True, "steps": [], "warnings": [], "purged": purge}

    def record(name: str, ok: bool, detail: str = "") -> None:
        report["steps"].append({"step": name, "ok": ok, "detail": detail})
        if not ok and detail:
            report["warnings"].append(f"{name}: {detail}")

    if os.geteuid() != 0:
        record("privileges", False, "removal requires root")
        report["ok"] = False
        return report

    applied = apply_mod.uninstall_artifacts(purge=purge)
    for step in applied["steps"]:
        record(step["step"], step["ok"], step["detail"])

    try:
        from . import appgate
        appgate.remove_all()
    except Exception as exc:  # pragma: no cover
        record("application control", False, str(exc))

    if purge:
        for path in (paths.STATE_DIR, paths.LOG_DIR, paths.CACHE_DIR):
            try:
                shutil.rmtree(path)
                record("purge", True, str(path))
            except OSError as exc:
                record("purge", False, f"{path}: {exc}")
    else:
        installstate.remove_marker()

    record("marker", True, "removed" if not purge else "removed (state purged)")
    audit.append("uninstall", "change", detail=f"purge={purge}", source="installer")
    return report
