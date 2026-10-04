"""Audit log: append-only JSON lines under /var/log/sudaeon/audit.log.

Written by root owned components (helper, sentinel, setuid verifier, PAM
module).  Reading requires the master password (the GUI goes through the
helper), which is why the file itself is mode 0600 root:root.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from . import paths
from .util import now_iso, run

RESULTS = ("allow", "deny", "prompt", "master-ok", "master-fail", "error", "info", "change")

MAX_BYTES = 2 * 1024 * 1024
KEEP_LINES = 5000


def log_path() -> Path:
    return paths.AUDIT_LOG


def append(action: str, result: str, *, user: str = "", uid: int | None = None,
           source: str = "cli", detail: str = "", extra: dict[str, Any] | None = None) -> None:
    """Append one audit record (never raises - auditing must not break policy)."""
    try:
        path = log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.parent.exists():          # pragma: no cover - defensive
            return
        entry = {
            "ts": now_iso(),
            "action": action,
            "result": result,
            "user": user,
            "uid": uid if uid is not None else os.getuid(),
            "source": source,
            "pid": os.getpid(),
        }
        if detail:
            entry["detail"] = detail[:800]
        if extra:
            entry["extra"] = {k: v for k, v in extra.items() if isinstance(v, (str, int, float, bool))}
        line = json.dumps(entry, sort_keys=True) + "\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
        try:
            if path.stat().st_size > MAX_BYTES:
                rotate()
        except OSError:
            pass
    except Exception:  # pragma: no cover - best effort only
        pass


def rotate() -> None:
    """Rotate the audit log, keeping one previous generation."""
    path = log_path()
    if not path.exists():
        return
    old = paths.AUDIT_LOG_OLD
    try:
        if old.exists():
            old.unlink()
        path.rename(old)
        os.chmod(old, 0o600)
    except OSError:
        return


def read(limit: int = 200, *, since: datetime | None = None,
         results: Iterable[str] | None = None,
         user: str | None = None) -> list[dict[str, Any]]:
    """Return the most recent entries (newest last)."""
    entries = _read_file(log_path()) + (_read_file(paths.AUDIT_LOG_OLD) if paths.AUDIT_LOG_OLD.exists() else [])
    entries.sort(key=lambda item: item.get("ts", ""))
    if since is not None:
        cutoff = since.isoformat()
        entries = [item for item in entries if item.get("ts", "") >= cutoff]
    if results:
        wanted = set(results)
        entries = [item for item in entries if item.get("result") in wanted]
    if user:
        entries = [item for item in entries if item.get("user") == user]
    return entries[-limit:]


def _read_file(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if isinstance(item, dict):
                    out.append(item)
    except (OSError, PermissionError):
        return out
    return out


def summary(since: datetime | None = None) -> dict[str, Any]:
    entries = read(limit=5000, since=since)
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.get("result", "?")] = counts.get(entry.get("result", "?"), 0) + 1
    fails = sum(count for result, count in counts.items() if result in {"master-fail", "deny"})
    return {
        "total": len(entries),
        "counts": counts,
        "failures": fails,
        "since": (since or (datetime.now() - timedelta(days=1))).isoformat(),
    }


def clear() -> bool:
    """Truncate the audit log (root only).  Returns True on success."""
    try:
        path = log_path()
        if path.exists():
            with open(path, "wb"):
                pass
            os.chmod(path, 0o600)
        return True
    except OSError:
        return False


def format_entry(entry: dict[str, Any]) -> str:
    stamp = str(entry.get("ts", ""))[:19].replace("T", " ")
    user = entry.get("user") or "?"
    action = entry.get("action") or "?"
    result = entry.get("result") or "?"
    detail = entry.get("detail") or ""
    suffix = f" ({detail})" if detail else ""
    return f"{stamp}  {result:<11} {user:<12} {action}{suffix}"
