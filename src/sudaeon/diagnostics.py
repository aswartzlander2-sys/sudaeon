"""``sudaeon doctor`` - check that enforcement is actually wired up."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from . import audit, config, installstate, pam as pam_mod, paths, vault
from .util import have, read_text, run, which
from .version import APP_VERSION


def _check(name: str, status: str, detail: str, hint: str = "") -> dict[str, Any]:
    return {"name": name, "status": status, "detail": detail, "hint": hint}


def run_checks() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    policy = vault.load_policy()

    installed = installstate.is_installed()
    checks.append(_check("installed", "ok" if installed else "fail",
                         installstate.find_conflict() or "not installed",
                         "" if installed else "run 'sudo sudaeon install'"))

    marker_version = installstate.installed_version()
    if installed:
        status = "ok" if marker_version == APP_VERSION else "warn"
        checks.append(_check("version", status,
                             f"installed {marker_version or '?'}, program {APP_VERSION}",
                             "" if status == "ok" else "run 'sudo sudaeon repair' after upgrading"))

    if policy is None:
        checks.append(_check("policy", "fail", "no policy file", "run 'sudo sudaeon install'"))
        return {"checks": checks, "ok": False, "root": os.geteuid() == 0}

    checks.append(_check("policy", "ok", config.summary(policy)))

    record = vault.read_master_record()
    checks.append(_check("master password",
                         "ok" if record else "fail",
                         "verifier present" if record else "no master password set",
                         "" if record else "run 'sudaeon setup'"))
    checks.append(_check("vault",
                         "ok" if paths.VAULT_FILE.exists() else "warn",
                         vault.vault_info().get("path", ""),
                         "" if paths.VAULT_FILE.exists() else "run 'sudo sudaeon repair'"))

    binary = vault.chkpwd_binary()
    if binary is None:
        checks.append(_check("verifier binary", "fail", "sudaeon-chkpwd is missing",
                             "rebuild and reinstall Sudaeon"))
    else:
        mode = oct(binary.stat().st_mode & 0o7777)
        setuid = bool(binary.stat().st_mode & 0o4000)
        checks.append(_check("verifier binary",
                             "ok" if setuid else "fail",
                             f"{binary} mode {mode}",
                             "" if setuid else "run: sudo chmod 4755 " + str(binary)))

    module_path = paths.PAM_MODULE if paths.PAM_MODULE.exists() else paths.PAM_MODULE_ALT
    checks.append(_check("pam module",
                         "ok" if module_path.exists() else "fail",
                         str(module_path),
                         "" if module_path.exists() else "run 'sudo sudaeon repair'"))
    services = pam_mod.installed_services()
    checks.append(_check("pam services",
                         "ok" if services else ("warn" if not policy.get("enabled") else "fail"),
                         ", ".join(services) or "no service file patched",
                         "" if services else "run 'sudo sudaeon repair'"))
    if services and "sudo" not in services:
        checks.append(_check("pam sudo", "warn", "sudo is not gated",
                             "run 'sudo sudaeon repair'"))

    sentinel_unit = paths.SYSTEMD_SENTINEL_UNIT
    checks.append(_check("sentinel unit",
                         "ok" if sentinel_unit.exists() else "fail",
                         str(sentinel_unit),
                         "" if sentinel_unit.exists() else "run 'sudo sudaeon repair'"))
    if which("systemctl"):
        proc = run(["systemctl", "is-active", "sudaeon-sentinel.service"], timeout=10)
        active = (proc.stdout or b"").decode().strip()
        want = "active" if policy.get("enabled") else "inactive"
        checks.append(_check("sentinel service",
                             "ok" if active in {want, "activating"} else "warn",
                             active or "unknown",
                             "" if active == want else
                             "run 'sudo systemctl restart sudaeon-sentinel'"))

    sudoers = paths.SUDOERS_FILE
    checks.append(_check("sudoers entry",
                         "ok" if sudoers.exists() else "warn",
                         str(sudoers),
                         "" if sudoers.exists() else "run 'sudo sudaeon repair'"))

    polkit_rules = paths.POLKIT_RULES_FILE
    checks.append(_check("polkit rules",
                         "ok" if polkit_rules.exists() else "warn",
                         str(polkit_rules),
                         "" if polkit_rules.exists() else "run 'sudo sudaeon repair'"))

    conf = paths.ENFORCEMENT_CONF
    checks.append(_check("enforcement.conf",
                         "ok" if conf.exists() else "fail",
                         str(conf),
                         "" if conf.exists() else "run 'sudo sudaeon repair'"))
    if conf.exists():
        text = read_text(conf, "")
        checks.append(_check("enforcement rendering",
                             "ok" if "max_attempts=" in text else "warn",
                             f"{len(text.splitlines())} lines"))

    summary = audit.summary()
    checks.append(_check("audit log",
                         "ok" if have("audit") or paths.AUDIT_LOG.exists() else "warn",
                         f"{summary['total']} entries, {summary['failures']} failures in the "
                         f"last day"))

    failures = [item for item in checks if item["status"] == "fail"]
    warns = [item for item in checks if item["status"] == "warn"]
    return {
        "checks": checks,
        "ok": not failures,
        "failures": len(failures),
        "warnings": len(warns),
        "root": os.geteuid() == 0,
        "summary": config.summary(policy),
    }


def format_report(report: dict[str, Any]) -> str:
    symbols = {"ok": " ok ", "warn": "warn", "fail": "FAIL"}
    lines = ["Sudaeon diagnostics", "==================="]
    for item in report["checks"]:
        lines.append(f"[{symbols.get(item['status'], '?')}] {item['name']:<20} {item['detail']}")
        if item["hint"] and item["status"] != "ok":
            lines.append(f"        hint: {item['hint']}")
    lines.append("")
    lines.append("result: " + ("everything looks good" if report["ok"]
                               else f"{report.get('failures', 0)} problem(s), "
                                    f"{report.get('warnings', 0)} warning(s)"))
    return "\n".join(lines)


def repair() -> dict[str, Any]:
    """Regenerate every enforcement artifact from the current policy."""
    from . import apply as apply_mod
    policy = vault.load_policy()
    if policy is None:
        return {"ok": False, "error": "no policy found - run 'sudo sudaeon install'"}
    report = apply_mod.apply_all(policy)
    return {"ok": report.get("ok", False), "report": report}
