"""User accounts, roles and session information."""

from __future__ import annotations

import json
import os
import pwd
from typing import Any, Iterable

from . import config, paths
from .util import (group_members, groups_of, is_admin_user, now_iso, run, username_of,
                   which)

SYSTEM_UID_MAX = 1000


def current_username(uid: int | None = None) -> str:
    uid = os.getuid() if uid is None else uid
    return username_of(uid) or str(uid)


def gecos_name(gecos: str) -> str:
    return (gecos or "").split(",")[0].strip()


def session_map() -> dict[int, dict[str, Any]]:
    """uid -> session information (from loginctl when available)."""
    out: dict[int, dict[str, Any]] = {}
    if not which("loginctl"):
        return out
    proc = run(["loginctl", "list-sessions", "--json=short"], timeout=10)
    text = (proc.stdout or "").strip()
    sessions: list[dict[str, Any]] = []
    if text.startswith("["):
        try:
            sessions = json.loads(text)
        except ValueError:
            sessions = []
    if not sessions:
        # older systemd: plain text table
        proc = run(["loginctl", "list-sessions", "--no-legend"], timeout=10)
        for line in (proc.stdout or "").splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            sessions.append({"session": parts[0], "uid": _int(parts[1]), "user": parts[2],
                             "seat": parts[3] if len(parts) > 3 else "",
                             "type": "", "state": "active"})
    for session in sessions:
        if not isinstance(session, dict):
            continue
        uid = _int(session.get("uid"))
        if uid is None:
            user = session.get("user")
            if isinstance(user, str):
                try:
                    uid = pwd.getpwnam(user).pw_uid
                except KeyError:
                    continue
        entry = {
            "session": str(session.get("session", "")),
            "uid": uid,
            "user": session.get("user") or username_of(uid) or "",
            "seat": session.get("seat") or "",
            "tty": session.get("tty") or "",
            "type": session.get("type") or "",
            "state": session.get("state") or "",
            "active": str(session.get("state", "")).lower() in {"active", "online"},
        }
        previous = out.get(uid)
        if previous is None or (entry["active"] and not previous.get("active")):
            out[uid] = entry
    return out


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def list_users(policy: dict[str, Any] | None = None, *, include_system: bool = False,
               include_root: bool = False) -> list[dict[str, Any]]:
    """Accounts that can be given a Sudaeon role."""
    sessions = session_map()
    users: list[dict[str, Any]] = []
    for entry in pwd.getpwall():
        system = entry.pw_uid < SYSTEM_UID_MAX or entry.pw_uid >= 60000
        if system and not include_system:
            continue
        if entry.pw_name == "nobody":
            continue
        if entry.pw_name == "root" and not include_root:
            continue
        shell = entry.pw_shell or ""
        groups = groups_of(entry.pw_name)
        role = config.role_for(policy, entry.pw_name) if policy else None
        session = sessions.get(entry.pw_uid) or {}
        users.append({
            "name": entry.pw_name,
            "uid": entry.pw_uid,
            "gid": entry.pw_gid,
            "full_name": gecos_name(entry.pw_gecos),
            "home": entry.pw_dir,
            "shell": shell,
            "system": system,
            "groups": groups,
            "sudoer": is_admin_user(entry.pw_name),
            "role": role,
            "role_label": config.ROLE_LABELS.get(role, "") if role else "",
            "explicit_role": bool(policy and (policy.get("users", {}).get("roles") or {})
                                  .get(entry.pw_name)),
            "logged_in": bool(session),
            "session": session,
            "login_shell_ok": not shell.endswith(("nologin", "false")),
        })
    users.sort(key=lambda item: (item["system"], item["uid"]))
    return users


def policy_users(policy: dict[str, Any]) -> list[str]:
    """Usernames the policy currently applies to."""
    names = [entry["name"] for entry in list_users(policy) if config.is_subject(policy, entry["name"])]
    return names


def administrators(policy: dict[str, Any]) -> list[str]:
    return [entry["name"] for entry in list_users(policy)
            if config.role_for(policy, entry["name"]) == config.ROLE_ADMIN]


def summarize_roles(policy: dict[str, Any]) -> dict[str, int]:
    counts = {config.ROLE_ADMIN: 0, config.ROLE_EXEMPT: 0, config.ROLE_REGULAR: 0,
              "system": 0, "total": 0}
    for entry in list_users(policy, include_system=False):
        role = config.role_for(policy, entry["name"])
        counts[role] = counts.get(role, 0) + 1
        counts["total"] += 1
    return counts


# ---------------------------------------------------------------------------
# the sudaeon-admins group (used by the sudoers drop-in)
# ---------------------------------------------------------------------------

def admin_group_exists() -> bool:
    import grp
    try:
        grp.getgrnam(paths.ADMIN_GROUP if hasattr(paths, "ADMIN_GROUP") else "sudaeon-admins")
        return True
    except KeyError:
        return False


def sync_admin_group(policy: dict[str, Any], *, apply: bool = True) -> dict[str, Any]:
    """Make the ``sudaeon-admins`` group match the Administrator role."""
    from .version import ADMIN_GROUP
    wanted = set(administrators(policy))
    result: dict[str, Any] = {"group": ADMIN_GROUP, "wanted": sorted(wanted),
                              "added": [], "removed": [], "errors": [], "applied": False}
    if not apply:
        return result
    if os.geteuid() != 0:
        result["errors"].append("must be root to change group membership")
        return result
    if not which("groupadd") or not which("gpasswd"):
        result["errors"].append("groupadd/gpasswd not available")
        return result
    if not admin_group_exists():
        proc = run(["groupadd", "--system", ADMIN_GROUP], timeout=10)
        if proc.returncode != 0:
            result["errors"].append(
                (proc.stderr or "").strip() or "groupadd failed")
            return result
    current = set(group_members(ADMIN_GROUP))
    for name in sorted(wanted - current):
        proc = run(["gpasswd", "-a", name, ADMIN_GROUP], timeout=10)
        if proc.returncode == 0:
            result["added"].append(name)
        else:
            result["errors"].append(f"could not add {name}: "
                                    f"{(proc.stderr or '').strip()}")
    for name in sorted(current - wanted):
        proc = run(["gpasswd", "-d", name, ADMIN_GROUP], timeout=10)
        if proc.returncode == 0:
            result["removed"].append(name)
        else:
            result["errors"].append(f"could not remove {name}: "
                                    f"{(proc.stderr or '').strip()}")
    result["applied"] = True
    return result


def ensure_user_in_group(username: str, group: str) -> bool:
    if os.geteuid() != 0 or not which("gpasswd"):
        return False
    return run(["gpasswd", "-a", username, group], timeout=10).returncode == 0


def sessions_of(username: str) -> list[dict[str, Any]]:
    return [entry for entry in session_map().values() if entry.get("user") == username]


def user_record(username: str) -> dict[str, Any] | None:
    for entry in list_users(include_system=True, include_root=True):
        if entry["name"] == username:
            return entry
    return None


def stamp() -> str:
    return now_iso()
