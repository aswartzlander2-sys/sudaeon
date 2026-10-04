"""Installation detection and the on-disk installation marker.

``/var/lib/sudaeon/install.json`` is written by ``sudaeon install`` and removed
by ``sudaeon uninstall``.  It is what makes "Sudaeon is already installed on
your system" possible: Sudaeon installs system wide (one instance per computer),
never per user account.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from . import paths
from .util import now_iso, read_json, run, which, write_json

MARKER_VERSION = 1


def read_marker() -> dict[str, Any] | None:
    data = read_json(paths.INSTALL_MARKER, None)
    return data if isinstance(data, dict) else None


def write_marker(policy: dict[str, Any]) -> dict[str, Any]:
    install = policy.setdefault("install", {})
    marker = {
        "marker_version": MARKER_VERSION,
        "instance_id": install.get("instance_id") or "",
        "installed_at": install.get("installed_at") or now_iso(),
        "installed_by": install.get("installed_by") or "",
        "installed_version": install.get("installed_version") or "",
        "layout": str(paths.STATE_DIR),
    }
    install["id"] = marker["instance_id"]
    install["installed_at"] = marker["installed_at"]
    install["installed_by"] = marker["installed_by"]
    install["installed_version"] = marker["installed_version"]
    write_json(paths.INSTALL_MARKER, marker, mode=0o644)
    return marker


def remove_marker() -> None:
    try:
        paths.INSTALL_MARKER.unlink()
    except OSError:
        pass


def is_installed() -> bool:
    return paths.INSTALL_MARKER.exists()


def _dpkg_installed() -> bool:
    if not which("dpkg-query"):
        return False
    proc = run(["dpkg-query", "-W", "-f=${Status}", "sudaeon"], timeout=10)
    return "install ok installed" in (proc.stdout or "")


def find_conflict() -> str | None:
    """Return a human readable reason when Sudaeon is already installed."""
    marker = read_marker()
    if marker:
        where = marker.get("installed_at", "an unknown time")
        who = marker.get("installed_by") or "unknown user"
        version = marker.get("installed_version") or "?"
        return (f"installed on this computer at {where} by {who} (version {version})")
    if paths.LIB_DIR.exists() and any(paths.LIB_DIR.iterdir()):
        return f"Sudaeon files are present in {paths.LIB_DIR}"
    if paths.pam_module_installed() is not None:
        return "the Sudaeon PAM module is present in /lib/security"
    if _dpkg_installed():
        return "the sudaeon package is installed"
    return None


def installation_details() -> dict[str, Any]:
    return {
        "installed": is_installed(),
        "marker": read_marker(),
        "conflict": find_conflict(),
        "state_dir": str(paths.STATE_DIR),
        "bin": str(paths.CLI_BIN),
        "lib_dir": str(paths.LIB_DIR),
        "pam_module": str(paths.pam_module_installed() or paths.PAM_MODULE),
        "policy_file": str(paths.POLICY_FILE),
        "policy_exists": paths.POLICY_FILE.exists(),
        "vault_exists": paths.VAULT_FILE.exists(),
        "master_verifier_exists": paths.MASTER_VERIFIER.exists(),
        "sentinel_unit": str(paths.SYSTEMD_SENTINEL_UNIT),
        "package_installed": _dpkg_installed(),
    }


def new_instance_id() -> str:
    from .util import random_hex
    return random_hex(8)


def version_matches() -> bool:
    from .version import APP_VERSION
    marker = read_marker() or {}
    return marker.get("installed_version") == APP_VERSION


def installed_version() -> str | None:
    marker = read_marker() or {}
    version = marker.get("installed_version")
    return version if isinstance(version, str) else None


def write_lock_file(pid: int) -> None:
    try:
        paths.RUN_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(paths.RUN_DIR, 0o755)
        (paths.RUN_DIR / "install.lock").write_text(str(pid), encoding="utf-8")
    except OSError:
        pass


def clear_lock_file() -> None:
    try:
        (paths.RUN_DIR / "install.lock").unlink()
    except OSError:
        pass
