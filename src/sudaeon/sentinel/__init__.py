"""The Sudaeon sentinel: the root daemon that enforces policy outside of PAM.

Responsibilities
----------------
* hold the systemd-logind inhibitors that make a blocked shutdown, reboot or
  suspend fail even for privileged desktop tools,
* watch the power/sleep buttons and the lid switch (exclusive ``EVIOCGRAB`` so
  the desktop environment cannot act on them first) and apply the
  "Allow Power Button to Bypass" setting,
* receive polkit denials from ``sudaeon-polkit-guard`` and ask the active
  session for the master password, completing the original action when the
  password is correct,
* keep every component in step with ``/var/lib/sudaeon/policy.json``.
"""

from __future__ import annotations

import json
import os
import socket
from typing import Any

from .. import paths
from ..util import read_json

SENTINEL_VERSION = 1


def running() -> bool:
    pid_file = paths.SENTINEL_PID
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def control(payload: dict[str, Any], *, timeout: float = 5.0) -> dict[str, Any] | None:
    """Send a control message to a running sentinel (root only)."""
    path = paths.sentinel_socket()
    if not path.exists():
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(path))
            sock.sendall((json.dumps(payload) + "\n").encode())
            data = b""
            while b"\n" not in data:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
    except (OSError, socket.timeout):
        return None
    try:
        return json.loads(data.decode(errors="replace").strip() or "{}")
    except ValueError:
        return None


def status() -> dict[str, Any]:
    info: dict[str, Any] = {
        "running": running(),
        "socket": str(paths.sentinel_socket()),
        "socket_exists": paths.sentinel_socket().exists(),
        "state": read_json(paths.SENTINEL_STATE, {}) or {},
    }
    response = control({"kind": "status"}) if running() else None
    if response:
        info.update(response)
        info["running"] = True
    return info
