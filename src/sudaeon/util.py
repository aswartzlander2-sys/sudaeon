"""Small shared helpers: files, JSON, processes, users, notifications."""

from __future__ import annotations

import grp
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from . import paths


# ---------------------------------------------------------------------------
# logging
# ---------------------------------------------------------------------------

DEBUG = bool(os.environ.get("SUDAEON_DEBUG"))
PREFIX = "sudaeon"


def _emit(stream, level: str, message: str) -> None:
    stamp = datetime.now().strftime("%H:%M:%S")
    print(f"{PREFIX}[{stamp}] {level}: {message}", file=stream, flush=True)


def log(message: str) -> None:
    _emit(sys.stderr, "info", message)


def debug(message: str) -> None:
    if DEBUG:
        _emit(sys.stderr, "debug", message)


def warn(message: str) -> None:
    _emit(sys.stderr, "warning", message)


def error(message: str) -> None:
    _emit(sys.stderr, "error", message)


# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------

def is_root() -> bool:
    return os.geteuid() == 0


def invoking_uid() -> int:
    """The uid of the human who started the process, not the effective one."""
    for name in ("PKEXEC_UID", "SUDO_UID"):
        value = os.environ.get(name)
        if value and value.isdigit():
            return int(value)
    return os.getuid()


def username_of(uid: int) -> str | None:
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError):
        return None


def uid_of(username: str) -> int | None:
    try:
        return pwd.getpwnam(username).pw_uid
    except KeyError:
        return None


def home_of(username: str) -> str | None:
    try:
        return pwd.getpwnam(username).pw_dir
    except KeyError:
        return None


def gid_of(username: str) -> int | None:
    try:
        return pwd.getpwnam(username).pw_gid
    except KeyError:
        return None


def group_exists(name: str) -> bool:
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


def group_members(name: str) -> list[str]:
    try:
        return sorted(grp.getgrnam(name).gr_mem)
    except KeyError:
        return []


def user_in_group(username: str, group: str) -> bool:
    try:
        record = pwd.getpwnam(username)
    except KeyError:
        return False
    if record.pw_gid == _gid(group):
        return True
    return username in group_members(group)


def _gid(name: str) -> int:
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return -1


#: Groups that mean "this account can become root on Ubuntu".
ADMIN_GROUPS = ("sudo", "admin", "wheel")


def is_admin_user(username: str) -> bool:
    """True when the account belongs to one of the administrator groups."""
    if not username:
        return False
    return any(user_in_group(username, name) for name in ADMIN_GROUPS)


def groups_of(username: str) -> list[str]:
    try:
        record = pwd.getpwnam(username)
    except KeyError:
        return []
    names = {grp.getgrgid(record.pw_gid).gr_name}
    for entry in grp.getgrall():
        if username in entry.gr_mem:
            names.add(entry.gr_name)
    return sorted(names)


def _gecos(value: str) -> str:
    return (value or "").split(",")[0].strip()


# ---------------------------------------------------------------------------
# processes
# ---------------------------------------------------------------------------

def run(argv: Sequence[str], *, timeout: float = 20.0, input_text: str | None = None,
        env: dict[str, str] | None = None, check: bool = False,
        cwd: str | None = None, user: str | None = None) -> subprocess.CompletedProcess:
    """Run a command and collect its output.

    The command is always run with text I/O, so ``proc.stdout`` and
    ``proc.stderr`` are ``str`` (never ``bytes``).  Callers that need the bytes
    of a process they started themselves should use ``subprocess`` directly.
    """
    argv = [str(item) for item in argv]
    kwargs: dict[str, Any] = {
        "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "stdin": subprocess.PIPE,
        "text": True, "timeout": timeout, "env": env, "cwd": cwd,
    }
    if user is not None and hasattr(os, "geteuid") and os.geteuid() == 0:
        kwargs["user"] = user
        kwargs["group"] = user
        kwargs.pop("env")
        kwargs["env"] = env
    debug("run: " + " ".join(argv))
    try:
        completed = subprocess.run(argv, input=input_text, **kwargs)  # noqa: S603
    except FileNotFoundError:
        return subprocess.CompletedProcess(argv, 127, "", f"{argv[0]}: not found")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", f"{argv[0]}: timed out")
    except OSError as exc:
        return subprocess.CompletedProcess(argv, 126, "", str(exc))
    if check and completed.returncode != 0:
        raise RuntimeError(f"{argv[0]} failed with {completed.returncode}: "
                           f"{(completed.stderr or '').strip()}")
    return completed


def run_text(argv: Sequence[str], **kwargs: Any) -> str:
    return run(argv, **kwargs).stdout or ""


def which(program: str) -> str | None:
    return shutil.which(program)


def have(program: str) -> bool:
    return which(program) is not None


# ---------------------------------------------------------------------------
# files
# ---------------------------------------------------------------------------

def ensure_dir(path: Path, mode: int = 0o755) -> Path:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, mode)
    except OSError:
        pass
    return path


def atomic_write(path: Path, data: str | bytes, *, mode: int = 0o644,
                 owner: tuple[int, int] | None = None) -> None:
    """Write a file atomically, with the requested permissions."""
    path = Path(path)
    ensure_dir(path.parent)
    binary = isinstance(data, bytes)
    payload = data if binary else data.encode("utf-8")
    handle = tempfile.NamedTemporaryFile(dir=str(path.parent), prefix=f".{path.name}.",
                                         delete=False)
    temporary = Path(handle.name)
    try:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    finally:
        handle.close()
    os.chmod(temporary, mode)
    if owner is not None:
        try:
            os.chown(temporary, owner[0], owner[1])
        except OSError:
            pass
    os.replace(temporary, path)
    try:
        os.chmod(path, mode)
    except OSError:
        pass
    _fsync_dir(path.parent)


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def read_text(path: Path, default: str = "") -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return default


def write_text(path: Path, data: str, *, mode: int = 0o644) -> None:
    atomic_write(path, data, mode=mode)


def read_json(path: Path, default: Any = None) -> Any:
    try:
        with open(str(path), "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def write_json(path: Path, data: Any, *, mode: int = 0o600, indent: int = 2) -> None:
    atomic_write(path, json.dumps(data, indent=indent, sort_keys=True) + "\n", mode=mode)


def copy_file(source: Path, target: Path, *, mode: int | None = None) -> None:
    ensure_dir(Path(target).parent)
    shutil.copy2(str(source), str(target))
    if mode is not None:
        os.chmod(target, mode)


# ---------------------------------------------------------------------------
# time
# ---------------------------------------------------------------------------

def now() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now().replace(microsecond=0).isoformat()


def parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp


def local_now() -> datetime:
    return datetime.now()


def random_hex(bytes_count: int = 16) -> str:
    return os.urandom(bytes_count).hex()


# ---------------------------------------------------------------------------
# desktop notifications
# ---------------------------------------------------------------------------

def notify(title: str, body: str = "", *, urgency: str = "normal",
           icon: str = "", user: str | None = None) -> bool:
    """Send a desktop notification to a logged-in user (best effort)."""
    if not have("notify-send"):
        return False
    env = None
    if user:
        env = desktop_env_for(user)
    argv = ["notify-send", "--app-name", paths.APP_NAME, "--urgency", urgency]
    if icon:
        argv += ["--icon", icon]
    argv += [title, body]
    completed = run(argv, timeout=5, env=env)
    return completed.returncode == 0


def desktop_env_for(user: str) -> dict[str, str]:
    """Environment variables that let a GUI program speak to the session of ``user``."""
    env = dict(os.environ)
    uid = uid_of(user)
    if uid is not None:
        env["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"
    env.setdefault("DISPLAY", ":0")
    env["DBUS_SESSION_BUS_ADDRESS"] = env.get(
        "DBUS_SESSION_BUS_ADDRESS", f"unix:path=/run/user/{uid}/bus" if uid else "")
    return env


def wall(message: str) -> None:
    if have("wall"):
        run(["wall", "-n", message], timeout=5)


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------

def choose(condition: bool, when_true: Any, when_false: Any) -> Any:
    return when_true if condition else when_false


def flatten(items: Iterable[Iterable[Any]]) -> list[Any]:
    return [item for group in items for item in group]
