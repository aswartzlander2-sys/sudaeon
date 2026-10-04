"""Insertion and removal of pam_sudaeon.so in /etc/pam.d.

Sudaeon never rewrites a PAM service file: it inserts a single line and can
remove exactly that line again, so upgrading or uninstalling cannot damage the
system's authentication stack.  A copy of every file that was touched is kept
in ``/var/lib/sudaeon/backup``.
"""

from __future__ import annotations

import os
import shutil
from typing import Any

from . import paths
from .util import atomic_write, log, read_text, run, which

MODULE = "pam_sudaeon.so"
BACKUP_DIRNAME = "backup"

# service file -> Sudaeon action
SERVICES: dict[str, str] = {
    "sudo": "sudo",
    "sudo-i": "sudo",
    "su": "sudo",
    "su-l": "sudo",
    "pkexec": "sudo",
    "polkit-1": "sudo",
    "passwd": "user_management",
    "chsh": "user_management",
    "chfn": "user_management",
    "gpasswd": "user_management",
    "chpasswd": "user_management",
    "login": "root_login",
    "gdm-password": "root_login",
    "lightdm": "root_login",
    "sddm": "root_login",
}

# Actions handled by pam_sm_chauthtok (the "password" stack) instead of the
# "auth" stack.
CHAUTHTOK_ACTIONS = {"user_management"}


def module_line(service: str, action: str) -> str:
    kind = "password" if action in CHAUTHTOK_ACTIONS else "auth"
    return f"{kind} requisite pam_sudaeon.so action={action}"


def _backup_path(service: str):
    return paths.STATE_DIR / BACKUP_DIRNAME / f"pam-{service}.orig"


def backup_service(service: str, path) -> None:
    target = _backup_path(service)
    if target.exists() or not path.exists():
        return
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    except OSError as exc:  # pragma: no cover
        log(f"could not back up {path}: {exc}")


def _insert_into(text: str, line: str) -> tuple[str, str]:
    """Return (new_text, note) with ``line`` inserted in the right place."""
    lines = text.splitlines()
    kind = line.split()[0]
    # 1. immediately before the include of the shared stack
    shared = "common-auth" if kind == "auth" else "common-password"
    for index, existing in enumerate(lines):
        stripped = existing.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith("@include") and shared in stripped:
            lines.insert(index, line)
            return "\n".join(lines) + "\n", f"inserted before @include {shared}"
        if stripped.startswith(f"{kind} include") and shared in stripped:
            lines.insert(index, line)
            return "\n".join(lines) + "\n", f"inserted before {kind} include {shared}"
    # 2. before the first stack entry of the same kind
    for index, existing in enumerate(lines):
        stripped = existing.strip()
        if stripped.startswith(f"{kind} "):
            lines.insert(index, line)
            return "\n".join(lines) + "\n", f"inserted before the first {kind} line"
    # 3. append
    lines.append(line)
    return "\n".join(lines) + "\n", "appended at the end"


def _remove_from(text: str) -> tuple[str, bool]:
    kept = [line for line in text.splitlines() if MODULE not in line]
    return "\n".join(kept) + "\n", len(kept) != len(text.splitlines())


def install_module() -> tuple[bool, str]:
    """Copy pam_sudaeon.so into the PAM module directory."""
    source = None
    for candidate in (paths.LIB_DIR / "pam_sudaeon.so",
                      paths.PACKAGE_DIR.parent.parent / "build" / "pam_sudaeon.so"):
        if candidate.exists():
            source = candidate
            break
    if source is None:
        return False, "pam_sudaeon.so has not been built"
    targets = [paths.PAM_MODULE]
    if not paths.PAM_MODULE.parent.exists():
        targets = [paths.PAM_MODULE_ALT]
    installed = False
    errors = []
    for target in targets:
        try:
            if target.parent.exists():
                shutil.copy2(source, target)
                os.chmod(target, 0o644)
                installed = True
        except OSError as exc:
            errors.append(f"{target}: {exc}")
    if not installed:
        return False, "; ".join(errors) or "no PAM module directory found"
    return True, f"installed {source.name}"


def remove_module() -> None:
    for candidate in (paths.PAM_MODULE, paths.PAM_MODULE_ALT):
        try:
            candidate.unlink()
        except OSError:
            pass


def installed_services() -> list[str]:
    found = []
    for service in SERVICES:
        path = paths.PAM_DIR / service
        text = read_text(path, "")
        if MODULE in text:
            found.append(service)
    return sorted(found)


def apply(policy: dict[str, Any], *, enabled: bool = True) -> dict[str, Any]:
    """Insert (or remove) the module in every managed service file."""
    report: dict[str, Any] = {"steps": [], "module": None}

    ok, detail = install_module()
    report["module"] = {"ok": ok, "detail": detail}
    report["steps"].append({"service": "pam_sudaeon.so", "ok": ok, "detail": detail})

    for service, action in sorted(SERVICES.items()):
        path = paths.PAM_DIR / service
        if not path.exists():
            report["steps"].append({"service": service, "ok": True,
                                    "detail": "not present on this system"})
            continue
        text = read_text(path, "")
        line = module_line(service, action)
        desired = enabled and policy.get("enabled") is not False
        if not desired:
            if MODULE in text:
                new_text, changed = _remove_from(text)
                if changed:
                    backup_service(service, path)
                    atomic_write(path, new_text, mode=0o644)
                    report["steps"].append({"service": service, "ok": True,
                                            "detail": "Sudaeon line removed"})
                    continue
            report["steps"].append({"service": service, "ok": True, "detail": "no change"})
            continue
        if MODULE in text:
            current = next((candidate for candidate in text.splitlines()
                            if MODULE in candidate), "")
            if current.strip() == line:
                report["steps"].append({"service": service, "ok": True,
                                        "detail": "already installed"})
                continue
            text, _ = _remove_from(text)
        new_text, note = _insert_into(text, line)
        backup_service(service, path)
        try:
            atomic_write(path, new_text, mode=0o644)
        except OSError as exc:
            report["steps"].append({"service": service, "ok": False, "detail": str(exc)})
            continue
        report["steps"].append({"service": service, "ok": True, "detail": note})
    return report


def revert() -> dict[str, Any]:
    """Remove every Sudaeon line from the PAM configuration."""
    report: dict[str, Any] = {"steps": [], "module": None}
    for service in sorted(SERVICES):
        path = paths.PAM_DIR / service
        if not path.exists():
            continue
        text = read_text(path, "")
        if MODULE not in text:
            continue
        new_text, changed = _remove_from(text)
        if not changed:
            continue
        backup_service(service, path)
        try:
            atomic_write(path, new_text, mode=0o644)
            report["steps"].append({"service": service, "ok": True, "detail": "line removed"})
        except OSError as exc:
            report["steps"].append({"service": service, "ok": False, "detail": str(exc)})
    remove_module()
    report["module"] = {"ok": True, "detail": "pam_sudaeon.so removed"}
    return report


def verify() -> tuple[bool, str]:
    """Sanity check the PAM configuration after an edit."""
    if not which("pamtester") and not paths.PAM_DIR.exists():
        return True, "no PAM directory"
    missing = [service for service in SERVICES
               if (paths.PAM_DIR / service).exists()
               and MODULE not in read_text(paths.PAM_DIR / service, "")]
    if missing and installed_services():
        return False, "the module is missing from: " + ", ".join(missing)
    return True, f"module present in {len(installed_services())} service files"


def status() -> dict[str, Any]:
    return {
        "services": installed_services(),
        "module_installed": paths.PAM_MODULE.exists() or paths.PAM_MODULE_ALT.exists(),
        "module_path": str(paths.PAM_MODULE if paths.PAM_MODULE.exists() else paths.PAM_MODULE_ALT),
    }
