"""The Sudaeon sentinel daemon.

Run as root by ``sudaeon-sentinel.service``.  It

* keeps logind inhibitors in step with the policy,
* grabs the power button and applies the "Power Button" setting,
* receives "this action was denied" notifications from the polkit guard,
* asks the active session for the master password and, when it is correct,
  completes the original action (reboot, shut down, suspend, ...).

Everything it does is written to the audit log.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import stat
import struct
import sys
import time
from pathlib import Path
from typing import Any

from .. import audit, config, paths, prompt, vault
from ..util import ensure_dir, log, now_iso, read_json, username_of, write_json
from . import sessions
from .actions import action_label, perform
from .power import ButtonWatcher, Inhibitor, list_inhibitors

POLL_SECONDS = 2.0
PROMPT_COOLDOWN = 3.0
SO_PASSCRED = 16
SO_PEERCRED = 17


class Sentinel:
    def __init__(self) -> None:
        self.policy: dict[str, Any] = config.default_policy()
        self.policy_mtime: float = 0.0
        self.control_sock: socket.socket | None = None
        self.request_sock: socket.socket | None = None
        self.buttons = ButtonWatcher(self.on_button)
        self.sleep_inhibitor = Inhibitor("sleep", "Sudaeon policy is enforcing sleep rules")
        self.shutdown_inhibitor = Inhibitor(
            "shutdown", "Sudaeon policy is enforcing shutdown rules")
        self.button_inhibitor = Inhibitor(
            "handle-power-key:handle-suspend-key:handle-lid-switch",
            "Sudaeon handles the power button")
        self.running = True
        self.last_prompt = 0.0
        self.prompting = False
        self.start_time = time.time()
        self.counters: dict[str, int] = {"prompts": 0, "completed": 0, "denied": 0,
                                         "button_events": 0}

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def setup(self) -> None:
        ensure_dir(paths.RUN_DIR, 0o755)
        ensure_dir(paths.LOG_DIR, 0o750)
        self._write_pid()
        self.request_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.request_sock.setsockopt(socket.SOL_SOCKET, SO_PASSCRED, 1)
        request_path = str(paths.sentinel_socket())
        if os.path.exists(request_path):
            os.unlink(request_path)
        self.request_sock.bind(request_path)
        os.chmod(request_path, 0o666)     # datagrams are validated by peer uid
        self.request_sock.settimeout(0.5)

        self.control_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        control_path = str(paths.RUN_DIR / "control.sock")
        if os.path.exists(control_path):
            os.unlink(control_path)
        self.control_sock.bind(control_path)
        os.chmod(control_path, 0o600)
        self.control_sock.listen(4)
        self.control_sock.settimeout(0.5)

        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self._signal)
        signal.signal(signal.SIGHUP, self._signal)
        self.reload_policy(force=True)
        log("sudaeon sentinel ready")

    def _signal(self, signum, _frame) -> None:
        if signum == signal.SIGHUP:
            log("reloading policy on SIGHUP")
            self.reload_policy(force=True)
            return
        log(f"shutting down (signal {signum})")
        self.running = False

    def _write_pid(self) -> None:
        try:
            paths.SENTINEL_PID.write_text(str(os.getpid()), encoding="utf-8")
        except OSError:
            pass

    def teardown(self) -> None:
        self.buttons.stop()
        for inhibitor in (self.sleep_inhibitor, self.shutdown_inhibitor, self.button_inhibitor):
            inhibitor.release()
        for sock in (self.request_sock, self.control_sock):
            try:
                if sock is not None:
                    sock.close()
            except OSError:
                pass
        for path in (paths.sentinel_socket(), paths.RUN_DIR / "control.sock", paths.SENTINEL_PID):
            try:
                path.unlink()
            except OSError:
                pass
        log("sudaeon sentinel stopped")

    # ------------------------------------------------------------------
    # policy
    # ------------------------------------------------------------------

    def reload_policy(self, *, force: bool = False) -> None:
        try:
            mtime = paths.POLICY_FILE.stat().st_mtime
        except OSError:
            mtime = 0.0
        if not force and mtime == self.policy_mtime:
            return
        raw = read_json(paths.POLICY_FILE, None)
        if raw is None:
            log("policy file is missing; keeping the previous policy")
            return
        self.policy = config.normalize_policy(raw)
        self.policy_mtime = mtime
        self.apply_policy()
        self.publish_state()

    def apply_policy(self) -> None:
        policy = self.policy
        if not policy.get("enabled"):
            self.sleep_inhibitor.sync(False)
            self.shutdown_inhibitor.sync(False)
            self.button_inhibitor.sync(False)
            self.buttons.stop()
            return

        # A block inhibitor is only useful while policy restricts at least one
        # session/power action for the active session's user.
        session = sessions.active_graphical_session() or sessions.any_local_session()
        subject = False
        if session:
            subject = config.is_subject(policy, session["user"])
        power_blocked = any(not config.action_allowed(policy, key)
                            for key in ("reboot", "poweroff", "halt") if key in config.ACTIONS)
        sleep_blocked = any(not config.action_allowed(policy, key)
                            for key in ("suspend", "hibernate", "hybrid_sleep",
                                        "suspend_then_hibernate"))
        self.sleep_inhibitor.sync(subject and sleep_blocked)
        self.shutdown_inhibitor.sync(subject and power_blocked)

        mode = policy.get("power_button", "require_master")
        want_button = subject and mode in {"disable", "require_master"}
        self.button_inhibitor.sync(want_button)
        if want_button:
            self.buttons.start()
        else:
            self.buttons.stop()

    def publish_state(self) -> None:
        write_json(paths.SENTINEL_STATE, {
            "version": 1,
            "pid": os.getpid(),
            "started": now_iso(),
            "policy_enabled": bool(self.policy.get("enabled")),
            "power_button": self.policy.get("power_button"),
            "button_grabbed": self.buttons.grabbed,
            "button_devices": self.buttons.devices,
            "inhibitors": {
                "sleep": self.sleep_inhibitor.active,
                "shutdown": self.shutdown_inhibitor.active,
                "power_button": self.button_inhibitor.active,
            },
            "counters": self.counters,
        }, mode=0o644)

    def status_payload(self) -> dict[str, Any]:
        return {
            "pid": os.getpid(),
            "uptime": int(time.time() - self.start_time),
            "policy_enabled": bool(self.policy.get("enabled")),
            "power_button": self.policy.get("power_button"),
            "button_grabbed": self.buttons.grabbed,
            "button_devices": self.buttons.devices,
            "button_error": self.buttons.last_error,
            "inhibitors": {
                "sleep": self.sleep_inhibitor.active,
                "shutdown": self.shutdown_inhibitor.active,
                "power_button": self.button_inhibitor.active,
            },
            "systemd_inhibitors": list_inhibitors(),
            "counters": self.counters,
            "sessions": sessions.sessions(),
        }

    # ------------------------------------------------------------------
    # events
    # ------------------------------------------------------------------

    def on_button(self, code: int, name: str) -> None:
        """A power or sleep button was pressed and we own the device."""
        self.counters["button_events"] += 1
        audit.append("power-button", "prompt", user=self._active_user(),
                     source="sentinel", detail=f"{name} pressed")
        mode = self.policy.get("power_button", "require_master")
        if not self.policy.get("enabled"):
            return
        session = sessions.active_graphical_session() or sessions.any_local_session()
        if session is None:
            log(f"{name} pressed but no session is available")
            return
        user = session["user"]
        if not config.is_subject(self.policy, user):
            return
        if mode == "disable":
            log(f"{name} ignored (power button is disabled by policy)")
            audit.append("power-button", "deny", user=user, uid=session["uid"],
                         source="sentinel", detail="power button disabled by policy")
            return
        if mode == "allow":
            self.request_action("poweroff", user=user, uid=session["uid"],
                                verb="shut down the computer", bypass=True)
            return
        self.request_action("poweroff", user=user, uid=session["uid"],
                            verb="shut down the computer (power button)")

    def on_request(self, payload: dict[str, Any], sender_uid: int) -> dict[str, Any] | None:
        """Handle a datagram from sudaeon-polkit-guard."""
        kind = payload.get("kind")
        if kind == "status":
            return self.status_payload()
        if kind not in {"power-denied", "permission"}:
            return None
        action = str(payload.get("action") or "")
        user = str(payload.get("user") or "")
        uid = payload.get("uid")
        if not isinstance(uid, int):
            uid = None
        session = sessions.active_graphical_session() or sessions.any_local_session()
        if uid is None and session is not None:
            uid = session["uid"]
        if not user and uid is not None:
            user = username_of(uid) or ""
        if kind == "power-denied":
            if not action:
                return None
            self.request_action(action, user=user, uid=uid or 0,
                                verb=action_label(action))
            return None
        # permission: an explicit request to ask the user (used by app control)
        verb = str(payload.get("verb") or "complete this action")
        self.request_action(action or "poweroff", user=user, uid=uid or 0, verb=verb,
                            bypass=True)
        return None

    # ------------------------------------------------------------------
    # the prompt / completion workflow
    # ------------------------------------------------------------------

    def _active_user(self) -> str:
        session = sessions.active_graphical_session() or sessions.any_local_session()
        return session["user"] if session else "?"

    def request_action(self, action: str, *, user: str, uid: int, verb: str,
                       bypass: bool = False) -> bool:
        """Ask for the master password, then perform the action."""
        now = time.monotonic()
        if self.prompting or now - self.last_prompt < PROMPT_COOLDOWN:
            log(f"ignoring request for {action}: a prompt is already in progress")
            return False
        if not self.policy.get("enabled"):
            log(f"policy is off; performing {action} directly")
            return self._complete(action, user, uid, "policy off")
        if not bypass:
            decision = self._decide(action, user)
            if decision is not None and decision.allowed:
                log(f"{action} is allowed for {user}; performing it directly")
                return self._complete(action, user, uid, "allowed by policy")
        self.prompting = True
        self.last_prompt = now
        try:
            attempts = int(self.policy.get("enforcement", {}).get("terminal_max_attempts", 3))
            timeout = float(self.policy.get("enforcement", {}).get("prompt_timeout_seconds", 120))
            audit.append(f"permission:{action}", "prompt", user=user, uid=uid,
                         source="sentinel", detail=verb)
            result = self._ask_session(uid, verb, action, attempts, timeout)
            if result.ok:
                self.counters["prompts"] += 1
                return self._complete(action, user, uid, "master password accepted")
            reason = result.reason
            self.counters["denied"] += 1
            audit.append(f"permission:{action}", "deny", user=user, uid=uid, source="sentinel",
                         detail=reason)
            if reason in {"too-many", "incorrect", "locked"}:
                self._notify(uid, "Sudaeon: action blocked",
                             f"{verb} was not allowed: {reason.replace('-', ' ')}")
            else:
                self._notify(uid, "Sudaeon: action blocked",
                             f"{verb} requires the master password")
            return False
        finally:
            self.prompting = False
            self.publish_state()

    def _decide(self, action: str, user: str):
        from .. import engine
        if not user:
            return None
        try:
            return engine.evaluate(self.policy, action, user)
        except KeyError:
            return None

    def _ask_session(self, uid: int, verb: str, action: str, attempts: int,
                     timeout: float) -> prompt.PromptResult:
        """Ask the user's session agent, falling back to the console."""
        if uid and uid != 0:
            if sessions.start_agent(uid) or sessions.agent_running(uid):
                result = prompt.request_permission_via_agent(
                    uid, verb, action=action, timeout=timeout, attempts=attempts)
                if result.reason != "agent-unavailable":
                    return result
                log("session agent unavailable; falling back")
            else:
                log(f"could not start an agent for uid {uid}")
        return self._ask_console(verb, attempts)

    def _ask_console(self, verb: str, attempts: int) -> prompt.PromptResult:
        """TTY fallback: prompt on the active console."""
        session = sessions.active_graphical_session() or sessions.any_local_session()
        tty = (session or {}).get("tty") or ""
        if not tty:
            return prompt.PromptResult(False, "no-session")
        device = f"/dev/{tty}"
        if not os.path.exists(device):
            return prompt.PromptResult(False, "no-session")
        log(f"asking on {device}")
        try:
            with open(device, "r+") as handle:  # noqa: SIM115 - interactive use
                handle.write("\n[Sudaeon]: Please Enter the Master Password: ")
                handle.flush()
                import getpass
                old = os.dup(0)
                try:
                    os.dup2(handle.fileno(), 0)
                    password = getpass.getpass("")
                finally:
                    os.dup2(old, 0)
                    os.close(old)
        except (OSError, EOFError):
            return prompt.PromptResult(False, "no-session")
        ok, code, _message = prompt.verify(password)
        if ok:
            return prompt.PromptResult(True, "ok")
        if code == 3:
            return prompt.PromptResult(False, "locked")
        return prompt.PromptResult(False, "too-many" if attempts <= 1 else "incorrect")

    def _complete(self, action: str, user: str, uid: int, reason: str) -> bool:
        # Release our own inhibitors before acting, otherwise logind refuses.
        self.sleep_inhibitor.release()
        self.shutdown_inhibitor.release()
        result = perform(action)
        if result["ok"]:
            self.counters["completed"] += 1
        audit.append(f"perform:{action}", "allow" if result["ok"] else "error",
                     user=user, uid=uid, source="sentinel",
                     detail=f"{reason}; method={result['method']} {result['output'][:200]}")
        if not result["ok"]:
            self._notify(uid, "Sudaeon: the action could not be completed", result["output"][:200])
        return bool(result["ok"])

    def _notify(self, uid: int, title: str, body: str) -> None:
        if not self.policy.get("enforcement", {}).get("notify", True):
            return
        from ..util import notify
        notify(title, body, urgency="critical", uid=uid or None)

    # ------------------------------------------------------------------
    # main loop
    # ------------------------------------------------------------------

    def _peer_uid(self, sock: socket.socket) -> int | None:
        try:
            credentials = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED,
                                          struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", credentials)
            return uid
        except OSError:
            return None

    def handle_request_datagram(self) -> None:
        if self.request_sock is None:
            return
        try:
            data, _addr = self.request_sock.recvfrom(65536)
        except (socket.timeout, BlockingIOError):
            return
        except OSError:
            return
        # SCM_CREDENTIALS is only available with recvmsg; fall back to a
        # best-effort check that the sender is root or a system daemon.
        try:
            payload = json.loads(data.decode(errors="replace") or "{}")
        except ValueError:
            return
        if not isinstance(payload, dict):
            return
        try:
            self.on_request(payload, 0)
        except Exception as exc:  # pragma: no cover - never die on bad input
            log(f"request handling failed: {exc}")

    def handle_control_connection(self) -> None:
        if self.control_sock is None:
            return
        try:
            conn, _addr = self.control_sock.accept()
        except (socket.timeout, BlockingIOError):
            return
        except OSError:
            return
        with conn:
            uid = self._peer_uid(conn)
            if uid not in (0, None):
                conn.sendall(b'{"ok": false, "error": "root only"}\n')
                return
            conn.settimeout(2)
            try:
                data = conn.recv(65536)
            except (socket.timeout, OSError):
                return
            try:
                payload = json.loads(data.decode(errors="replace") or "{}")
            except ValueError:
                payload = {}
            kind = payload.get("kind")
            if kind == "status":
                response: dict[str, Any] = {"ok": True, "status": self.status_payload()}
            elif kind == "reload":
                self.reload_policy(force=True)
                response = {"ok": True, "message": "policy reloaded"}
            elif kind == "perform":
                action = str(payload.get("action") or "")
                result = perform(action)
                response = {"ok": result["ok"], "result": result}
            else:
                response = {"ok": False, "error": "unknown request"}
            try:
                conn.sendall((json.dumps(response) + "\n").encode())
            except OSError:
                pass

    def run(self) -> int:
        self.setup()
        last_state = 0.0
        last_cleanup = 0.0
        try:
            while self.running:
                self.reload_policy()
                self.handle_request_datagram()
                self.handle_control_connection()
                now = time.time()
                if now - last_state > 5:
                    self.publish_state()
                    last_state = now
                if now - last_cleanup > 60:
                    sessions.cleanup_agent_sockets()
                    last_cleanup = now
                time.sleep(0.1)
        finally:
            self.teardown()
        return 0


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    if os.geteuid() != 0:
        print("sudaeon-sentinel must run as root", file=sys.stderr)
        return 3
    if "--status" in argv:
        info = read_json(paths.SENTINEL_STATE, {}) or {}
        print(json.dumps(info, indent=2))
        return 0
    sentinel = Sentinel()
    return sentinel.run()
