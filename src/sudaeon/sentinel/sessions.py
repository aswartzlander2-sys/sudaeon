"""Session helpers for the sentinel (logind queries, agent management)."""

from __future__ import annotations

import json
import os
import pwd
import subprocess
import time
from typing import Any

from .. import paths
from ..util import desktop_env_for, log, run, username_of, which


def _loginctl_json(*args: str) -> list[dict[str, Any]]:
    if not which("loginctl"):
        return []
    proc = run(["loginctl", *args], timeout=10)
    text = (proc.stdout or b"").decode(errors="replace").strip()
    if not text.startswith("["):
        return []
    try:
        parsed = json.loads(text)
    except ValueError:
        return []
    return [item for item in parsed if isinstance(item, dict)]


def sessions() -> list[dict[str, Any]]:
    entries = _loginctl_json("list-sessions", "--json=short")
    out: list[dict[str, Any]] = []
    for entry in entries:
        uid = entry.get("uid")
        if not isinstance(uid, int):
            user = entry.get("user")
            if isinstance(user, str):
                try:
                    uid = pwd.getpwnam(user).pw_uid
                except KeyError:
                    continue
            else:
                continue
        out.append({
            "uid": uid,
            "user": entry.get("user") or username_of(uid) or str(uid),
            "session": str(entry.get("session") or ""),
            "seat": entry.get("seat") or "",
            "type": entry.get("type") or "",
            "state": str(entry.get("state") or "").lower(),
            "tty": entry.get("tty") or "",
        })
    return out


def active_graphical_session() -> dict[str, Any] | None:
    """The session that currently owns the screen."""
    best: dict[str, Any] | None = None
    for entry in sessions():
        if entry["state"] not in {"active", "online"}:
            continue
        if entry["type"] not in {"wayland", "x11", "mir"}:
            continue
        if entry["uid"] == 0:
            continue
        if entry["state"] == "active":
            return entry
        best = best or entry
    return best


def active_session_for_user(uid: int) -> dict[str, Any] | None:
    for entry in sessions():
        if entry["uid"] == uid and entry["state"] in {"active", "online"}:
            if entry["type"] in {"wayland", "x11", "mir"}:
                return entry
    return None


def any_local_session() -> dict[str, Any] | None:
    for entry in sessions():
        if entry["uid"] != 0 and entry["type"] in {"wayland", "x11", "mir", "tty"}:
            return entry
    return None


def agent_running(uid: int) -> bool:
    path = paths.agent_socket(uid)
    if not path.exists():
        return False
    # a stale socket file is common after a crash; connect to be sure
    import socket
    try:
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(0.5)
        probe.connect(str(path))
        probe.close()
        return True
    except OSError:
        return False


def start_agent(uid: int) -> bool:
    """Launch the permission agent inside the user's graphical session."""
    if agent_running(uid):
        return True
    try:
        entry = pwd.getpwuid(uid)
    except KeyError:
        return False
    env = desktop_env_for(uid)
    argv = ["setpriv", f"--reuid={uid}", f"--regid={entry.pw_gid}", "--init-groups", "--"]
    argv += [str(paths.CLI_BIN), "agent", "--session"]
    full_env = dict(os.environ)
    full_env.update({key: value for key, value in env.items() if value})
    full_env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{uid}")
    try:
        subprocess.Popen(argv, env=full_env, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError as exc:
        log(f"could not start the agent for uid {uid}: {exc}")
        return False
    deadline = time.time() + 6
    while time.time() < deadline:
        if agent_running(uid):
            return True
        time.sleep(0.2)
    log(f"agent for uid {uid} did not come up")
    return False


def cleanup_agent_sockets() -> None:
    """Remove agent sockets whose session is gone."""
    if not paths.RUN_DIR.exists():
        return
    live = {entry["uid"] for entry in sessions()}
    for path in paths.RUN_DIR.glob("agent.*.sock"):
        try:
            uid = int(path.name.split(".")[1])
        except (IndexError, ValueError):
            continue
        if uid not in live:
            try:
                path.unlink()
            except OSError:
                pass
