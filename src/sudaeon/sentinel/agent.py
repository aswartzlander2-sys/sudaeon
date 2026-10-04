"""The per-session permission agent.

The sentinel listens on a root-owned socket and hands the file descriptor to an
agent process running **as the logged in user**, so the dialog appears inside
that user's graphical session (correct Wayland/X11 environment, correct theme).

Security notes
--------------
* The listening socket lives in ``/run/sudaeon`` (root owned, mode 0755) and is
  created **by the sentinel** with mode 0600 root:root.  The agent only inherits
  the file descriptor, so a user cannot bind a replacement socket at that path
  and cannot connect to it at all - a tampered session cannot approve anything.
* The agent verifies the password with the setuid ``sudaeon-chkpwd`` binary,
  which enforces the shared rate limit and writes the audit log.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from typing import Any

from .. import paths, prompt
from ..util import log, username_of

MAX_REQUEST = 65536


class Agent:
    def __init__(self, listen_fd: int, uid: int) -> None:
        self.listen_fd = listen_fd
        self.uid = uid
        self.sock: socket.socket | None = None
        self.running = True
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.sock = socket.fromfd(self.listen_fd, socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(1.0)
        self.thread = threading.Thread(target=self._serve, name="sudaeon-agent", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

    def _serve(self) -> None:
        while self.running:
            try:
                conn, _ = self.sock.accept()          # type: ignore[union-attr]
            except (socket.timeout, BlockingIOError):
                continue
            except OSError:
                return
            try:
                with conn:
                    self._handle(conn)
            except Exception as exc:  # pragma: no cover - never die on bad input
                log(f"agent request failed: {exc}")

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(5)
        try:
            data = conn.recv(MAX_REQUEST)
        except (socket.timeout, OSError):
            return
        try:
            request = json.loads(data.decode(errors="replace") or "{}")
        except ValueError:
            return
        if not isinstance(request, dict):
            return
        kind = request.get("kind")
        if kind == "ping":
            self._reply(conn, {"ok": True, "uid": self.uid,
                               "user": username_of(self.uid) or ""})
            return
        if kind != "permission":
            self._reply(conn, {"ok": False, "reason": "unknown request"})
            return
        self._reply(conn, self._ask(request))

    def _reply(self, conn: socket.socket, payload: dict[str, Any]) -> None:
        try:
            conn.sendall((json.dumps(payload) + "\n").encode())
        except OSError:
            pass

    def _ask(self, request: dict[str, Any]) -> dict[str, Any]:
        verb = str(request.get("verb") or "complete this action")
        attempts = int(request.get("attempts") or 3)
        try:
            result = prompt.gtk_ask(verb, attempts=attempts)
        except Exception as exc:
            log(f"agent: cannot show the permission dialog: {exc}")
            return {"ok": False, "reason": "no-display"}
        return {"ok": result.ok, "reason": result.reason,
                "user": username_of(self.uid) or ""}


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    uid = os.getuid()
    fd: int | None = None
    for index, item in enumerate(argv):
        if item == "--listen-fd" and index + 1 < len(argv):
            fd = int(argv[index + 1])
        elif item.startswith("--listen-fd="):
            fd = int(item.split("=", 1)[1])
    if fd is None:
        env_fd = os.environ.get("SUDAEON_AGENT_FD")
        if env_fd and env_fd.isdigit():
            fd = int(env_fd)
    if fd is None:
        log("agent: no listening socket was provided by the sentinel "
            "(the agent is started by sudaeon-sentinel)")
        return 3
    agent = Agent(fd, uid)
    agent.start()
    log(f"agent ready for uid {uid}")
    try:
        while agent.running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        agent.stop()
    return 0
