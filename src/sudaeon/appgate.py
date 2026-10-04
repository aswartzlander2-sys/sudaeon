"""Application control.

Blocked applications are gated by a desktop entry and PATH override that runs
``sudaeon app-launch <id>``.  The launcher checks the policy and, when the
application is blocked for the user, asks for the master password before
starting the real program.

Honest limitations (documented in docs/POLICY.md)
-------------------------------------------------
* Applications started from a path that is not the desktop entry or the
  overridden binary can bypass the gate.
* A technically skilled user can call the real binary directly.
Application control is a speed bump for ordinary users, not a sandbox - use
sudaeon's power/session and sudo enforcement for hard guarantees.
"""

from __future__ import annotations

import os
import shlex
import shutil
from pathlib import Path
from typing import Any

from . import config, desktop, paths
from .util import atomic_write, log, read_json, run, which, write_json

OVERRIDE_DIR = Path("/usr/local/share/applications")
BIN_OVERRIDE_DIR = Path("/usr/local/bin")


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------

def entry_dict(entry: desktop.DesktopEntry) -> dict[str, Any]:
    """The dictionary shape the policy stores for one application."""
    return {
        "id": entry.id,
        "path": str(entry.path),
        "name": entry.name,
        "exec": entry.exec_line,
        "icon": entry.icon,
        "comment": entry.comment,
        "categories": entry.category,
        "terminal": entry.terminal,
    }


def parse_desktop_file(path: Path) -> dict[str, Any] | None:
    """Dictionary form of one desktop entry (or ``None``)."""
    entry = desktop.read_entry(Path(path))
    return None if entry is None else entry_dict(entry)


def installed_apps(*, include_hidden: bool = False) -> list[dict[str, Any]]:
    """Every blockable desktop application, sorted by name.

    Entries in :data:`sudaeon.desktop.PROTECTED_IDS` are left out: blocking
    them would break the desktop or lock the administrator out.
    """
    return [entry_dict(entry) for entry in desktop.installed(include_user=False,
                                                             include_hidden=include_hidden)
            if not desktop.is_protected(entry.id)]


def binary_from_exec(exec_line: str) -> str | None:
    try:
        parts = shlex.split(exec_line)
    except ValueError:
        return None
    for part in parts:
        if part.startswith("%"):
            continue
        if part in {"env", "sh", "-c", "bash"}:
            continue
        candidate = shutil.which(part) if not os.path.isabs(part) else part
        if candidate and os.path.exists(candidate):
            return candidate
    return None


# ---------------------------------------------------------------------------
# overrides
# ---------------------------------------------------------------------------

def bare_id(app_id: str) -> str:
    """The id without the ``.desktop`` suffix (the form used in state files)."""
    return app_id[: -len(".desktop")] if app_id.endswith(".desktop") else app_id


def override_path(app_id: str) -> Path:
    name = app_id if app_id.endswith(".desktop") else f"{app_id}.desktop"
    return OVERRIDE_DIR / name


def sync(policy: dict[str, Any]) -> dict[str, Any]:
    """Create/remove the desktop overrides for the blocked application list."""
    report: dict[str, Any] = {"created": [], "removed": [], "errors": []}
    blocked = config.blocked_applications(policy)
    wanted = {entry["id"]: entry for entry in blocked
              if entry.get("id") and not desktop.is_protected(entry["id"])}
    bare = {bare_id(app_id) for app_id in wanted}

    for app_id, entry in wanted.items():
        try:
            OVERRIDE_DIR.mkdir(parents=True, exist_ok=True)
            original = str(entry.get("path") or "")
            exec_line = str(entry.get("exec") or "")
            body = (
                "[Desktop Entry]\n"
                "Type=Application\n"
                f"Name={entry.get('name') or app_id}\n"
                f"Comment={entry.get('comment') or 'Blocked by Sudaeon'}\n"
                f"Exec={paths.CLI_BIN} app-launch {app_id} %U\n"
                f"Icon={entry.get('icon') or 'com.sudaeon.Sudaeon'}\n"
                f"Terminal={'true' if entry.get('terminal') else 'false'}\n"
                "Categories=Sudaeon;\n"
                "X-Sudaeon-Blocked=true\n"
                f"X-Sudaeon-Original={original}\n"
                f"X-Sudaeon-OriginalExec={exec_line}\n"
            )
            atomic_write(override_path(app_id), body, mode=0o644)
            write_json(paths.appgate_meta(app_id), {
                "id": app_id,
                "name": entry.get("name"),
                "original_desktop": original,
                "exec": exec_line,
                "binary": binary_from_exec(exec_line) if exec_line else None,
                "added": entry.get("added"),
            }, mode=0o644)
            report["created"].append(app_id)
        except OSError as exc:
            report["errors"].append(f"{app_id}: {exc}")

        # a PATH shim so terminal launches are gated too
        binary = binary_from_exec(str(entry.get("exec") or ""))
        if binary and not binary.startswith(str(BIN_OVERRIDE_DIR)) and \
                not binary.startswith("/snap") and not binary.startswith("/var/lib/flatpak"):
            try:
                BIN_OVERRIDE_DIR.mkdir(parents=True, exist_ok=True)
                shim = BIN_OVERRIDE_DIR / Path(binary).name
                if not shim.exists() or "Sudaeon" in shim.read_text(errors="replace"):
                    atomic_write(shim, (
                        "#!/bin/sh\n"
                        f"# Sudaeon gate for {binary}\n"
                        f'exec {paths.CLI_BIN} app-launch {app_id} -- "$@"\n'
                    ), mode=0o755)
                    report["created"].append(str(shim))
            except OSError as exc:
                report["errors"].append(f"shim {binary}: {exc}")

    # drop overrides that are no longer configured
    if OVERRIDE_DIR.exists():
        for path in OVERRIDE_DIR.glob("*.desktop"):
            app_id = path.stem
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "X-Sudaeon-Blocked=true" in text and app_id not in bare:
                try:
                    path.unlink()
                    report["removed"].append(app_id)
                except OSError as exc:
                    report["errors"].append(f"{app_id}: {exc}")
    for meta in paths.APPGATE_DIR.glob("*.json") if paths.APPGATE_DIR.exists() else []:
        if meta.stem not in bare:
            try:
                meta.unlink()
                binary = (read_json(meta, {}) or {}).get("binary") if meta.exists() else None
                if binary:
                    shim = BIN_OVERRIDE_DIR / Path(binary).name
                    if shim.exists() and "Sudaeon gate" in shim.read_text(errors="replace"):
                        shim.unlink()
            except OSError:
                pass

    if which("update-desktop-database") and OVERRIDE_DIR.exists():
        run(["update-desktop-database", "-q", str(OVERRIDE_DIR)], timeout=30)
    return report


def remove_all() -> None:
    if OVERRIDE_DIR.exists():
        for path in OVERRIDE_DIR.glob("*.desktop"):
            try:
                if "X-Sudaeon-Blocked=true" in path.read_text(encoding="utf-8", errors="replace"):
                    path.unlink()
            except OSError:
                pass
    if BIN_OVERRIDE_DIR.exists():
        for path in BIN_OVERRIDE_DIR.iterdir():
            try:
                if path.is_file() and path.read_text(errors="replace").startswith("#!/bin/sh") \
                        and "Sudaeon gate" in path.read_text(errors="replace"):
                    path.unlink()
            except OSError:
                pass
    import shutil as _shutil
    try:
        if paths.APPGATE_DIR.exists():
            _shutil.rmtree(paths.APPGATE_DIR)
    except OSError:
        pass
    if which("update-desktop-database"):
        run(["update-desktop-database", "-q", str(OVERRIDE_DIR)], timeout=30)


# ---------------------------------------------------------------------------
# launching
# ---------------------------------------------------------------------------

FIELD_CODES = ("%f", "%F", "%u", "%U", "%d", "%D", "%n", "%N", "%i", "%c", "%k", "%v", "%m")


def build_command(exec_line: str, extra_args: list[str], *, icon: str = "") -> list[str]:
    """Expand a desktop Exec line, substituting supplied arguments."""
    try:
        parts = shlex.split(exec_line)
    except ValueError:
        parts = exec_line.split()
    command: list[str] = []
    consumed = False
    for part in parts:
        if part in FIELD_CODES or (part.startswith("%") and len(part) == 2):
            if part in {"%i"}:
                if icon:
                    command.extend(["-i", icon])
                continue
            if part in {"%c"}:
                command.append("Sudaeon")
                continue
            if part in {"%k", "%v", "%m", "%d", "%D", "%n", "%N"}:
                continue
            if extra_args and not consumed:
                command.extend(extra_args)
                consumed = True
            continue
        if "%" in part:
            replaced = part
            for code in ("%f", "%F", "%u", "%U"):
                if code in replaced and extra_args:
                    replaced = replaced.replace(code, extra_args[0])
            command.append(replaced)
            continue
        command.append(part)
    return [part for part in command if part]


def launch(app_id: str, extra_args: list[str]) -> int:
    """Run a gated application (called as ``sudaeon app-launch <id>``)."""
    from . import engine, vault
    from .util import invoking_uid, username_of

    meta = read_json(paths.appgate_meta(app_id), None)
    if not isinstance(meta, dict):
        log(f"application control: {app_id} is not configured")
        return 4
    exec_line = str(meta.get("exec") or "")
    if not exec_line:
        log(f"application control: no command recorded for {app_id}")
        return 4
    command = build_command(exec_line, extra_args, icon=str(meta.get("icon") or ""))
    if not command:
        log(f"application control: empty command for {app_id}")
        return 4

    from . import config as config_mod
    policy = vault.load_policy()
    user = username_of(invoking_uid()) or ""
    blocked = bool(policy) and config_mod.blocked_app(policy, app_id) is not None
    decision = None
    if policy is not None and blocked:
        decision = engine.evaluate(policy, "app_control", user, uid=invoking_uid())
    if decision is not None and not decision.allowed:
        from . import prompt
        name = str(meta.get("name") or app_id)
        if not prompt.request_permission(
                verb=f"open {name}", action="app_control", user=user,
                uid=invoking_uid(), title="Sudaeon Permission Manager",
                text="Please Enter the Master Password",  # exact wording required by the specification
                allow_app_override=True):
            log("Sudaeon: the master password was not accepted.")
            return 1
    try:
        os.execvp(command[0], command)
    except OSError as exc:
        log(f"Sudaeon: could not start {command[0]}: {exc}")
        return 5


def run_original(app_id: str, extra_args: list[str]) -> int:
    """Start the application without asking (used by exempt users)."""
    meta = read_json(paths.appgate_meta(app_id), None) or {}
    command = build_command(str(meta.get("exec") or ""), extra_args)
    if not command:
        return 4
    try:
        os.execvp(command[0], command)
    except OSError:
        return 5
