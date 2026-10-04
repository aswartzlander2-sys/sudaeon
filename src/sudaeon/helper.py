"""sudaeon-helper - the privileged half of Sudaeon.

Runs as root (through the sudoers entry installed for ``sudaeon-admins`` or
through pkexec) and performs every state change.  Two rules apply to all verbs:

1. only root, a Sudaeon Administrator or a member of ``sudaeon-admins`` may
   call it, and
2. verbs that change policy require the master password, which is verified with
   the setuid ``sudaeon-chkpwd`` binary (one implementation, rate limited and
   audited).

Protocol
--------
``sudaeon-helper <verb> [args]`` reads stdin:

* line 1: the master password (only for verbs marked ``master``),
* the rest: an optional JSON payload.

It always writes a single JSON object to stdout:
``{"ok": true, "message": "...", "data": {...}}`` or
``{"ok": false, "error": "..."}`` with a non-zero exit status.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable

from . import (apply as apply_mod, audit, config, installstate, pam as pam_mod, paths,
               users, vault)
from .util import (error, group_members, invoking_uid, log, now_iso, read_json, run,
                   username_of, write_json)
from .version import ADMIN_GROUP, APP_VERSION

# verbs that require the master password (read from stdin line 1)
MASTER_VERBS = {
    "set-policy", "set-role", "set-roles", "provision-master", "change-master",
    "show-recovery", "regenerate-recovery", "app-add", "app-remove", "audit-clear",
    "apply-enforcement", "set-enabled", "repair-vault", "uninstall",
}

# verbs reachable without a master password (administrators only)
ADMIN_VERBS = {
    "get-policy", "status", "doctor", "audit-tail", "vault-info", "sentinel-status",
    "service", "install", "reset-master", "install-check", "repair", "pam-apply",
    "pam-revert", "users-list", "version",
} | MASTER_VERBS

# Verbs that only somebody who is already root can reach.  They are the glue
# between dpkg and Sudaeon: postinst configures the system and prerm takes the
# hooks out again.  They are checked for root (like every helper call) and
# deliberately skip the administrator test, because the account that runs
# "apt install" is not an Administrator yet - the install itself is what makes
# it one.  Neither verb can change the master password or an existing policy.
PACKAGE_VERBS = {"configure-package", "unconfigure-package"}


class HelperFailure(Exception):
    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


def _ok(message: str = "", data: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"ok": True, "message": message, "data": data or {}}


def _fail(message: str) -> dict[str, Any]:
    return {"ok": False, "error": message}


# ---------------------------------------------------------------------------
# input parsing
# ---------------------------------------------------------------------------

def _read_stdin() -> tuple[str, str]:
    try:
        data = sys.stdin.read()
    except (OSError, UnicodeDecodeError):
        return "", ""
    if not data:
        return "", ""
    first, _, rest = data.partition("\n")
    return first.rstrip("\r"), rest


def _payload(text: str) -> dict[str, Any]:
    text = text.strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except ValueError as exc:
        raise HelperFailure(f"invalid JSON payload: {exc}") from exc
    if not isinstance(parsed, dict):
        raise HelperFailure("the JSON payload must be an object")
    return parsed


# ---------------------------------------------------------------------------
# authorisation
# ---------------------------------------------------------------------------

def caller_is_privileged() -> tuple[bool, str]:
    """Root, an Administrator, or a member of the sudaeon-admins group."""
    if os.geteuid() != 0:
        return False, "the helper must run as root"
    uid = invoking_uid()
    if uid == 0:
        return True, "root"
    name = username_of(uid)
    if not name:
        return False, "unknown caller"
    if name in group_members(ADMIN_GROUP):
        return True, f"{name} is in {ADMIN_GROUP}"
    policy = vault.load_policy()
    if policy is not None and config.can_open_dashboard(policy, name):
        return True, f"{name} is a Sudaeon Administrator"
    return False, (f"'{name}' is not a Sudaeon administrator. Ask an administrator to "
                   f"change your role, or use pkexec to authenticate as one.")


def verify_master(password: str, *, action: str = "helper",
                  source: str = "helper") -> bool:
    ok, code, message = vault.verify_master_via_chkpwd(password)
    audit.append(f"verify-master:{action}", "master-ok" if ok else "master-fail",
                 user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source=source,
                 detail=message or ("accepted" if ok else "incorrect"))
    if not ok:
        if code == 3:
            raise HelperFailure("Too many incorrect attempts. Please wait and try again.")
        if code == 2:
            raise HelperFailure(message or "the master password could not be verified")
        raise HelperFailure("The Password Entered was Incorrect")
    return True


def require_master(password: str, verb: str) -> None:
    if not password:
        raise HelperFailure("the master password is required")
    verify_master(password, action=verb)


# ---------------------------------------------------------------------------
# verbs
# ---------------------------------------------------------------------------

def _policy_or_default() -> dict[str, Any]:
    policy = vault.load_policy()
    if policy is None:
        raise HelperFailure("Sudaeon is not installed")
    return policy


def verb_version(_password: str, _payload: dict[str, Any]) -> dict[str, Any]:
    return _ok(f"Sudaeon {APP_VERSION}", {"version": APP_VERSION})


def verb_install_check(_password: str, _payload: dict[str, Any]) -> dict[str, Any]:
    conflict = installstate.find_conflict()
    return _ok("installed" if conflict else "not installed",
               {"conflict": conflict, "details": installstate.installation_details()})


def verb_install(password: str, payload: dict[str, Any]) -> dict[str, Any]:
    from . import installer
    if os.geteuid() != 0:
        raise HelperFailure("installation requires root")
    force = bool(payload.get("force"))
    invoking = payload.get("user") or username_of(invoking_uid()) or "root"
    report = installer.install(invoking_user=invoking, master_password=password or None,
                               force=force, from_package=bool(payload.get("from_package")))
    if not report.get("ok"):
        raise HelperFailure("; ".join(report.get("warnings") or ["installation failed"]))
    return _ok("Sudaeon installed", report)


def verb_configure_package(_password: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Finish an installation performed by dpkg (called from postinst).

    dpkg cannot ask for a master password, and on a fresh installation none
    exists yet, so this verb deliberately takes no password: it only writes the
    default policy and the enforcement hooks, never the verifier.
    """
    from . import installer
    if os.geteuid() != 0:
        raise HelperFailure("configuring Sudaeon requires root")
    user = str(payload.get("user") or "")
    if not user and invoking_uid():
        user = username_of(invoking_uid()) or ""
    report = installer.configure_from_package(invoking_user=user,
                                              force=bool(payload.get("force")))
    if not report.get("ok"):
        raise HelperFailure("; ".join(report.get("warnings") or
                                      ["the configuration failed"]))
    return _ok("Sudaeon is configured", report)


def verb_unconfigure_package(_password: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Remove the enforcement hooks before dpkg deletes the program (prerm)."""
    from . import installer
    if os.geteuid() != 0:
        raise HelperFailure("removing the Sudaeon hooks requires root")
    report = installer.revert_from_package(purge=bool(payload.get("purge")))
    return _ok("the Sudaeon enforcement hooks were removed", report)


def verb_uninstall(password: str, payload: dict[str, Any]) -> dict[str, Any]:
    from . import installer
    if os.geteuid() != 0:
        raise HelperFailure("removal requires root")
    if password:
        require_master(password, "uninstall")
    elif not payload.get("force"):
        raise HelperFailure("the master password is required to remove Sudaeon")
    report = installer.uninstall(purge=bool(payload.get("purge")))
    return _ok("Sudaeon removed", report)


def verb_get_policy(_password: str, _payload: dict[str, Any]) -> dict[str, Any]:
    policy = vault.load_policy()
    if policy is None:
        raise HelperFailure("Sudaeon is not installed")
    return _ok("policy", {"policy": policy, "summary": config.summary(policy)})


def verb_set_policy(password: str, payload: dict[str, Any]) -> dict[str, Any]:
    require_master(password, "set-policy")
    incoming = payload.get("policy")
    if not isinstance(incoming, dict):
        raise HelperFailure("no policy supplied")
    policy = config.normalize_policy(incoming)
    policy.setdefault("install", {})["instance_id"] = (
        (vault.load_policy() or {}).get("install", {}).get("instance_id", ""))
    installer_meta = (vault.load_policy() or {}).get("install", {})
    policy["install"] = installer_meta
    config.stamp_policy(policy)
    vault.save_policy(policy)
    report = apply_mod.apply_all(policy)
    audit.append("set-policy", "change", user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source="helper",
                 detail=f"enabled={policy.get('enabled')}")
    _refresh_vault_policy(password, policy)
    return _ok("Policy saved", {"report": report, "policy": policy,
                                "summary": config.summary(policy)})


def verb_set_enabled(password: str, payload: dict[str, Any]) -> dict[str, Any]:
    require_master(password, "set-enabled")
    policy = _policy_or_default()
    policy["enabled"] = bool(payload.get("enabled", not policy.get("enabled")))
    config.stamp_policy(policy)
    vault.save_policy(policy)
    report = apply_mod.apply_all(policy)
    _refresh_vault_policy(password, policy)
    state = "on" if policy["enabled"] else "off"
    audit.append("set-enabled", "change", user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source="helper", detail=f"Sudaeon turned {state}")
    return _ok(f"Sudaeon is now {state}", {"policy": policy, "report": report,
                                           "summary": config.summary(policy)})


def verb_set_role(password: str, payload: dict[str, Any]) -> dict[str, Any]:
    require_master(password, "set-role")
    policy = _policy_or_default()
    name = str(payload.get("user") or "")
    role = str(payload.get("role") or "")
    if not name or not users.user_record(name):
        raise HelperFailure(f"unknown user: {name!r}")
    if name == "root":
        raise HelperFailure("the root account is not managed by Sudaeon")
    config.set_role(policy, name, role)
    config.stamp_policy(policy)
    vault.save_policy(policy)
    report = apply_mod.apply_all(policy)
    _refresh_vault_policy(password, policy)
    audit.append("set-role", "change", user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source="helper",
                 detail=f"{name} -> {config.ROLE_LABELS.get(role, role)}")
    return _ok(f"{name} is now {config.ROLE_LABELS.get(role, role)}",
               {"policy": policy, "report": report})


def verb_set_roles(password: str, payload: dict[str, Any]) -> dict[str, Any]:
    require_master(password, "set-roles")
    policy = _policy_or_default()
    roles = payload.get("roles")
    if not isinstance(roles, dict):
        raise HelperFailure("no roles supplied")
    changed = []
    for name, role in roles.items():
        if name == "root" or not users.user_record(name):
            continue
        config.set_role(policy, name, str(role))
        changed.append(f"{name}:{role}")
    config.stamp_policy(policy)
    vault.save_policy(policy)
    report = apply_mod.apply_all(policy)
    _refresh_vault_policy(password, policy)
    audit.append("set-roles", "change", user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source="helper", detail=", ".join(changed)[:400])
    return _ok("Roles updated", {"policy": policy, "report": report})


def verb_apply_enforcement(password: str, payload: dict[str, Any]) -> dict[str, Any]:
    require_master(password, "apply-enforcement")
    policy = _policy_or_default()
    report = apply_mod.apply_all(policy)
    ok, message = pam_mod.verify()
    return _ok("Enforcement applied", {"report": report, "pam_verify": ok,
                                       "pam_message": message})


def verb_status(_password: str, _payload: dict[str, Any]) -> dict[str, Any]:
    from . import sentinel as sentinel_mod
    policy = vault.load_policy()
    data = {
        "version": APP_VERSION,
        "installed": installstate.is_installed(),
        "installation": installstate.installation_details(),
        "policy": policy,
        "summary": config.summary(policy) if policy else "not installed",
        "pam": pam_mod.status(),
        "vault": vault.vault_info(),
        "sentinel": sentinel_mod.status(),
        "audit": audit.summary(),
        "users": users.summarize_roles(policy) if policy else {},
    }
    return _ok("status", data)


def verb_doctor(_password: str, _payload: dict[str, Any]) -> dict[str, Any]:
    from . import diagnostics
    return _ok("diagnostics", diagnostics.run_checks())


def verb_users_list(_password: str, _payload: dict[str, Any]) -> dict[str, Any]:
    policy = vault.load_policy()
    if policy is None:
        raise HelperFailure("Sudaeon is not installed")
    entries = users.list_users(policy)
    return _ok("users", {"users": entries, "summary": users.summarize_roles(policy)})


def verb_audit_tail(_password: str, payload: dict[str, Any]) -> dict[str, Any]:
    limit = int(payload.get("limit") or 200)
    entries = audit.read(limit=limit)
    return _ok("audit", {"entries": entries, "summary": audit.summary()})


def verb_audit_clear(password: str, _payload: dict[str, Any]) -> dict[str, Any]:
    require_master(password, "audit-clear")
    ok = audit.clear()
    audit.append("audit-clear", "change", user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source="helper", detail="audit log cleared")
    if not ok:
        raise HelperFailure("the audit log could not be cleared")
    return _ok("Audit log cleared")


def verb_vault_info(_password: str, _payload: dict[str, Any]) -> dict[str, Any]:
    return _ok("vault", vault.vault_info())


def verb_provision_master(password: str, payload: dict[str, Any]) -> dict[str, Any]:
    """First run: store the master password, create the recovery key, enable policy."""
    if not password:
        raise HelperFailure("no master password supplied")
    policy = vault.load_policy()
    if policy is None:
        raise HelperFailure("Sudaeon is not installed")
    if vault.read_master_record() and not payload.get("overwrite"):
        conflict = "a master password is already set"
        if not payload.get("recovery_key"):
            raise HelperFailure(conflict)
    if payload.get("recovery_key"):
        result = vault.reset_master(password, recovery_key=str(payload["recovery_key"]))
    else:
        params = policy.get("advanced", {}).get("master_kdf")
        result = vault.provision(password, policy, params=params)
    policy = vault.load_policy() or policy
    if payload.get("enable", True):
        policy["enabled"] = True
    config.stamp_policy(policy)
    vault.save_policy(policy)
    report = apply_mod.apply_all(policy)
    vault.write_vault(password, {
        "version": 1,
        "created": now_iso(),
        "master_verifier": vault.read_master_record(),
        "recovery_key": result["recovery_key"],
        "recovery_created": now_iso(),
        "policy": policy,
        "history": [{"ts": now_iso(), "event": "initial setup"}],
    })
    audit.append("setup", "change", user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source="helper",
                 detail=f"master password created; policy {'enabled' if policy['enabled'] else 'disabled'}")
    return _ok("Master password saved", {
        "recovery_key": result["recovery_key"],
        "policy": policy,
        "report": report,
        "summary": config.summary(policy),
    })


def verb_change_master(_password: str, payload: dict[str, Any]) -> dict[str, Any]:
    old = str(payload.get("old") or "")
    new = str(payload.get("new") or "")
    if not old or not new:
        raise HelperFailure("both the old and the new master password are required")
    require_master(old, "change-master")
    result = vault.change_master(old, new)
    audit.append("change-master", "change", user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source="helper", detail="master password changed")
    return _ok("Master password changed", {"recovery_key": result["recovery_key"]})


def verb_reset_master(_password: str, payload: dict[str, Any]) -> dict[str, Any]:
    new = str(payload.get("new") or "")
    recovery = str(payload.get("recovery_key") or "")
    if not new:
        raise HelperFailure("a new master password is required")
    if recovery:
        result = vault.reset_master(new, recovery_key=recovery)
        audit.append("reset-master", "change", user=username_of(invoking_uid()) or "?",
                     uid=invoking_uid(), source="helper", detail="reset using the recovery key")
        return _ok("Master password reset", {"recovery_key": result["recovery_key"]})
    if os.geteuid() != 0 or not payload.get("force"):
        raise HelperFailure("resetting without the recovery key requires root and --force")
    if payload.get("new_password_confirm") not in (None, new):
        raise HelperFailure("the passwords do not match")
    result = vault.reset_master(new)
    audit.append("reset-master", "change", user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source="helper", detail="force reset by root")
    return _ok("Master password reset", {"recovery_key": result["recovery_key"]})


def verb_show_recovery(password: str, _payload: dict[str, Any]) -> dict[str, Any]:
    require_master(password, "show-recovery")
    key = vault.show_recovery_key(password)
    audit.append("show-recovery", "allow", user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source="helper", detail="recovery key displayed")
    return _ok("recovery key", {"recovery_key": key})


def verb_regenerate_recovery(password: str, _payload: dict[str, Any]) -> dict[str, Any]:
    require_master(password, "regenerate-recovery")
    key = vault.regenerate_recovery_key(password)
    audit.append("regenerate-recovery", "change", user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source="helper", detail="recovery key regenerated")
    return _ok("A new recovery key was created", {"recovery_key": key})


def verb_repair_vault(password: str, _payload: dict[str, Any]) -> dict[str, Any]:
    require_master(password, "repair-vault")
    policy = vault.load_policy()
    result = vault.repair(password, policy)
    audit.append("repair-vault", "change", user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source="helper", detail="vault rewritten")
    return _ok("Vault repaired", {"recovery_key": result["recovery_key"]})


def verb_repair(_password: str, _payload: dict[str, Any]) -> dict[str, Any]:
    policy = vault.load_policy()
    if policy is None:
        raise HelperFailure("no policy to repair - reinstall Sudaeon")
    report = apply_mod.apply_all(policy)
    audit.append("repair", "change", user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source="helper", detail="enforcement files regenerated")
    return _ok("Enforcement files regenerated", {"report": report})


def verb_pam_apply(password: str, payload: dict[str, Any]) -> dict[str, Any]:
    require_master(password, "pam-apply") if password else None
    policy = _policy_or_default()
    report = pam_mod.apply(policy, enabled=bool(payload.get("enabled", True)))
    return _ok("PAM updated", report)


def verb_pam_revert(_password: str, _payload: dict[str, Any]) -> dict[str, Any]:
    report = pam_mod.revert()
    return _ok("PAM reverted", report)


def verb_app_add(password: str, payload: dict[str, Any]) -> dict[str, Any]:
    require_master(password, "app-add")
    entry = payload.get("app")
    if not isinstance(entry, dict) or not entry.get("id"):
        raise HelperFailure("no application supplied")
    policy = _policy_or_default()
    blocked = policy.setdefault("applications", {}).setdefault("blocked", [])
    blocked[:] = [item for item in blocked if item.get("id") != entry["id"]]
    blocked.append(entry)
    config.stamp_policy(policy)
    vault.save_policy(policy)
    from . import appgate
    appgate.sync(policy)
    apply_mod.write_enforcement_conf(policy)
    _refresh_vault_policy(password, policy)
    audit.append("app-add", "change", user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source="helper", detail=f"blocked {entry.get('name')}")
    return _ok(f"{entry.get('name') or entry['id']} is now blocked", {"policy": policy})


def verb_app_remove(password: str, payload: dict[str, Any]) -> dict[str, Any]:
    require_master(password, "app-remove")
    app_id = str(payload.get("id") or "")
    if not app_id:
        raise HelperFailure("no application id supplied")
    policy = _policy_or_default()
    blocked = policy.setdefault("applications", {}).setdefault("blocked", [])
    blocked[:] = [item for item in blocked if item.get("id") != app_id]
    config.stamp_policy(policy)
    vault.save_policy(policy)
    from . import appgate
    appgate.sync(policy)
    apply_mod.write_enforcement_conf(policy)
    _refresh_vault_policy(password, policy)
    audit.append("app-remove", "change", user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source="helper", detail=f"unblocked {app_id}")
    return _ok("Application unblocked", {"policy": policy})


def verb_service(_password: str, payload: dict[str, Any]) -> dict[str, Any]:
    action = str(payload.get("action") or "status")
    if action not in {"start", "stop", "restart", "reload", "status", "enable", "disable"}:
        raise HelperFailure(f"unsupported service action: {action}")
    unit = str(payload.get("unit") or "sudaeon-sentinel.service")
    code, message = apply_mod.systemctl(action, unit)
    audit.append(f"service-{action}", "change", user=username_of(invoking_uid()) or "?",
                 uid=invoking_uid(), source="helper", detail=f"{unit}: {message}")
    return _ok(message or f"{unit} {action}", {"code": code, "output": message})


def verb_sentinel_status(_password: str, _payload: dict[str, Any]) -> dict[str, Any]:
    from . import sentinel as sentinel_mod
    return _ok("sentinel", sentinel_mod.status())


def _refresh_vault_policy(password: str, policy: dict[str, Any]) -> None:
    """Keep the encrypted vault in step with the active policy."""
    try:
        payload = vault.read_vault(password)
    except vault.VaultError:
        return
    payload["policy"] = policy
    payload["updated"] = now_iso()
    vault.write_vault(password, payload)


VERBS: dict[str, Callable[[str, dict[str, Any]], dict[str, Any]]] = {
    "version": verb_version,
    "install-check": verb_install_check,
    "install": verb_install,
    "uninstall": verb_uninstall,
    "get-policy": verb_get_policy,
    "set-policy": verb_set_policy,
    "set-enabled": verb_set_enabled,
    "set-role": verb_set_role,
    "set-roles": verb_set_roles,
    "apply-enforcement": verb_apply_enforcement,
    "status": verb_status,
    "doctor": verb_doctor,
    "users-list": verb_users_list,
    "audit-tail": verb_audit_tail,
    "audit-clear": verb_audit_clear,
    "vault-info": verb_vault_info,
    "provision-master": verb_provision_master,
    "change-master": verb_change_master,
    "reset-master": verb_reset_master,
    "show-recovery": verb_show_recovery,
    "regenerate-recovery": verb_regenerate_recovery,
    "repair-vault": verb_repair_vault,
    "repair": verb_repair,
    "configure-package": verb_configure_package,
    "unconfigure-package": verb_unconfigure_package,
    "pam-apply": verb_pam_apply,
    "pam-revert": verb_pam_revert,
    "app-add": verb_app_add,
    "app-remove": verb_app_remove,
    "service": verb_service,
    "sentinel-status": verb_sentinel_status,
}


def dispatch(argv: list[str]) -> int:
    """Entry point for the helper binary.  Returns a process exit status."""
    if not argv or argv[0] in {"-h", "--help", "help"}:
        print(json.dumps(_ok("Sudaeon helper", {"verbs": sorted(VERBS)})))
        return 0
    verb = argv[0]
    payload: dict[str, Any] = {}
    password = ""

    if os.geteuid() != 0:
        print(json.dumps(_fail("the Sudaeon helper must run as root")))
        return 3
    if verb not in VERBS:
        print(json.dumps(_fail(f"unknown helper verb: {verb}")))
        return 2

    try:
        password, rest = _read_stdin()
        payload = _payload(rest)
        if verb not in PACKAGE_VERBS:
            allowed, reason = caller_is_privileged()
            if not allowed:
                audit.append(f"helper:{verb}", "deny",
                             user=username_of(invoking_uid()) or "?",
                             uid=invoking_uid(), source="helper", detail=reason)
                raise HelperFailure(reason)
        if verb in MASTER_VERBS and not password:
            raise HelperFailure("the master password is required")
        result = VERBS[verb](password, payload)
    except HelperFailure as exc:
        print(json.dumps(_fail(str(exc))))
        return 1
    except vault.VaultError as exc:
        print(json.dumps(_fail(str(exc))))
        return 1
    except Exception as exc:  # pragma: no cover - defensive
        error(f"helper {verb} failed: {exc}")
        print(json.dumps(_fail(f"internal error: {exc}")))
        return 4

    print(json.dumps(result))
    return 0 if result.get("ok") else 1
