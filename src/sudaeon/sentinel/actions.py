"""Carrying out power and session actions (as root, after the master password)."""

from __future__ import annotations

from typing import Any

from .. import config
from ..util import log, run, which

# action key -> (systemctl verb, logind method, legacy command)
ACTION_COMMANDS: dict[str, tuple[str | None, str | None, list[str]]] = {
    "reboot": ("reboot", "Reboot", ["/sbin/reboot", "/usr/sbin/reboot", "reboot"]),
    "poweroff": ("poweroff", "PowerOff", ["/sbin/poweroff", "/usr/sbin/poweroff", "poweroff"]),
    "halt": ("halt", "Halt", ["/sbin/halt", "/usr/sbin/halt", "halt"]),
    "suspend": ("suspend", "Suspend", ["/usr/bin/systemctl", "suspend"]),
    "hibernate": ("hibernate", "Hibernate", ["/usr/bin/systemctl", "hibernate"]),
    "hybrid_sleep": ("hybrid-sleep", "HybridSleep",
                     ["/usr/bin/systemctl", "hybrid-sleep"]),
    "suspend_then_hibernate": ("suspend-then-hibernate", "SuspendThenHibernate",
                               ["/usr/bin/systemctl", "suspend-then-hibernate"]),
    "kexec": ("kexec", "KExec", ["/usr/bin/systemctl", "kexec"]),
    "soft_reboot": ("soft-reboot", "SoftReboot", ["/usr/bin/systemctl", "soft-reboot"]),
}

LOGIND_INTERFACE = "org.freedesktop.login1.Manager"
LOGIND_PATH = "/org/freedesktop/login1"


def _try(argv: list[str], timeout: float = 15) -> tuple[bool, str]:
    binary = argv[0]
    if binary.startswith("/") and not which(binary.lstrip("/")):
        pass
    if not which(argv[0]) and not (binary.startswith("/") and __import__("os").path.exists(binary)):
        return False, f"{argv[0]} is not available"
    proc = run(argv, timeout=timeout)
    output = ((proc.stdout or b"") + (proc.stderr or b"")).decode(errors="replace").strip()
    if proc.returncode == 0:
        return True, output
    return False, output or f"exit status {proc.returncode}"


def perform(action: str, *, timeout: float = 20) -> dict[str, Any]:
    """Run ``action``; returns {ok, method, output}."""
    spec = ACTION_COMMANDS.get(action)
    if spec is None:
        return {"ok": False, "method": "none", "output": f"{action} cannot be performed"}
    systemctl_verb, logind_method, legacy = spec

    attempts= list[tuple[str, list[str]]] = []
    if systemctl_verb and which("systemctl"):
        attempts.append(("systemctl", ["systemctl", "--no-block", systemctl_verb]))
        attempts.append(("systemctl-ignore-inhibit",
                         ["systemctl", "--no-block", "-i", systemctl_verb]))
    if logind_method and which("busctl"):
        attempts.append(("logind", ["busctl", "call", "org.freedesktop.login1", LOGIND_PATH,
                                    LOGIND_INTERFACE, logind_method, "b", "false"]))
    for candidate in legacy:
        if __import__("os").path.exists(candidate):
            attempts.append(("legacy", [candidate]))
            break

    errors: list[str] = []
    for method, argv in attempts:
        ok, output = _try(argv, timeout=timeout)
        if ok:
            log(f"action {action} performed via {method}")
            return {"ok": True, "method": method, "output": output}
        errors.append(f"{method}: {output}")
    log(f"action {action} failed: {'; '.join(errors)}")
    return {"ok": False, "method": "none", "output": "; ".join(errors)}


def action_label(action: str) -> str:
    try:
        return config.action(action).prompt_verb
    except KeyError:
        return action


def supported_actions() -> list[str]:
    return sorted(ACTION_COMMANDS)
