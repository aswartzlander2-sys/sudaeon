"""Power button / sleep button handling and logind inhibitors.

The kernel exposes the ACPI power button as an input device.  Keep the device
open exclusively (``EVIOCGRAB``) so that the desktop environment cannot act on
the key first: the sentinel then decides what happens, exactly like the
dashboard's "Allow Power Button to Bypass" setting says.

logind inhibitors are handled by keeping ``systemd-inhibit`` child processes
alive with ``--mode=block`` - the plain command line tool is used instead of a
D-Bus binding so the sentinel needs no extra dependencies.
"""

from __future__ import annotations

import fcntl
import os
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from ..util import log, run, which

# ---------------------------------------------------------------------------
# input device helpers
# ---------------------------------------------------------------------------

EVIOCGRAB = 0x40044590
EVIOCGNAME = 0x80006A06
EVIOCGBIT = lambda ev, length: 0x80000000 | (length << 16) | (0x20 + ev)  # noqa: E731

EV_SYN = 0x00
EV_KEY = 0x01
EV_SW = 0x05

KEY_POWER = 116
KEY_SUSPEND = 205
SW_LID = 0

EVENT_FORMAT = "llHHi"          # timeval + type + code + value
EVENT_SIZE = struct.calcsize(EVENT_FORMAT)

POWER_KEY_NAMES = {
    KEY_POWER: "power button",
    KEY_SUSPEND: "sleep button",
}


def _bit_is_set(bits: bytes, code: int) -> bool:
    index = code // 8
    if index >= len(bits):
        return False
    return bool(bits[index] & (1 << (code % 8)))


def device_name(fd: int) -> str:
    try:
        buffer = bytearray(256)
        fcntl.ioctl(fd, EVIOCGNAME, buffer)
        return buffer.split(b"\0")[0].decode(errors="replace")
    except OSError:
        return ""


def device_keys(fd: int, event_type: int, codes: list[int]) -> set[int]:
    """Which of ``codes`` does this device report?"""
    length = max(codes) // 8 + 1
    try:
        buffer = bytearray(length)
        fcntl.ioctl(fd, EVIOCGBIT(event_type, length), buffer)
    except OSError:
        return set()
    return {code for code in codes if _bit_is_set(bytes(buffer), code)}


def find_button_devices() -> list[tuple[Path, set[int]]]:
    """Return (device path, supported key codes) for power/sleep button devices."""
    found: list[tuple[Path, set[int]]] = []
    for path in sorted(Path("/dev/input").glob("event*")):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError:
            continue
        try:
            keys = device_keys(fd, EV_KEY, [KEY_POWER, KEY_SUSPEND])
            if keys:
                found.append((path, keys))
        finally:
            os.close(fd)
    return found


# ---------------------------------------------------------------------------
# the monitoring thread
# ---------------------------------------------------------------------------

class ButtonWatcher:
    """Grabs the power/sleep buttons and reports presses to a callback."""

    def __init__(self, callback: Callable[[int, str], None]) -> None:
        self.callback = callback
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._fds: list[int] = []
        self.grabbed = False
        self.devices: list[str] = []
        self.last_error = ""

    def start(self) -> bool:
        if self._thread is not None:
            return self.grabbed
        if not Path("/dev/input").exists():
            self.last_error = "/dev/input is not available"
            return False
        if os.geteuid() != 0:
            self.last_error = "root is required to grab the power button"
            return False
        devices = find_button_devices()
        if not devices:
            self.last_error = "no power or sleep button device found"
            return False
        for path, keys in devices:
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            except OSError as exc:
                self.last_error = f"{path}: {exc}"
                continue
            try:
                fcntl.ioctl(fd, EVIOCGRAB, 1)
            except OSError as exc:
                self.last_error = f"{path}: cannot grab ({exc})"
                os.close(fd)
                continue
            self._fds.append(fd)
            self.devices.append(f"{device_name(fd) or path}")
        if not self._fds:
            log(f"power button: not grabbed ({self.last_error})")
            return False
        self.grabbed = True
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="sudaeon-buttons", daemon=True)
        self._thread.start()
        log(f"power button grabbed: {', '.join(self.devices)}")
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        for fd in self._fds:
            try:
                fcntl.ioctl(fd, EVIOCGRAB, 0)
            except OSError:
                pass
            try:
                os.close(fd)
            except OSError:
                pass
        self._fds.clear()
        self.grabbed = False

    def _loop(self) -> None:
        last_press: dict[int, float] = {}
        while not self._stop.is_set():
            active = False
            for fd in list(self._fds):
                try:
                    data = os.read(fd, EVENT_SIZE * 32)
                except BlockingIOError:
                    continue
                except OSError:
                    continue
                active = True
                for offset in range(0, len(data) - EVENT_SIZE + 1, EVENT_SIZE):
                    _sec, _usec, ev_type, code, value = struct.unpack(
                        EVENT_FORMAT, data[offset:offset + EVENT_SIZE])
                    if ev_type != EV_KEY or code not in POWER_KEY_NAMES:
                        continue
                    if value != 1:                 # presses only, no repeats/releases
                        continue
                    now = time.monotonic()
                    if now - last_press.get(code, 0.0) < 1.0:
                        continue
                    last_press[code] = now
                    try:
                        self.callback(code, POWER_KEY_NAMES[code])
                    except Exception as exc:  # pragma: no cover - defensive
                        log(f"power button handler failed: {exc}")
            if not active:
                self._stop.wait(0.25)


# ---------------------------------------------------------------------------
# logind inhibitors
# ---------------------------------------------------------------------------

class Inhibitor:
    """A blocked logind inhibitor held by a long running systemd-inhibit child."""

    def __init__(self, what: str, why: str) -> None:
        self.what = what
        self.why = why
        self._proc: subprocess.Popen | None = None

    @property
    def active(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def acquire(self) -> bool:
        if self.active:
            return True
        if not which("systemd-inhibit"):
            log("systemd-inhibit is not available; inhibitors are disabled")
            return False
        argv = ["systemd-inhibit", f"--what={self.what}", "--who=Sudaeon",
                f"--why={self.why}", "--mode=block", "sleep", "infinity"]
        try:
            self._proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
        except OSError as exc:
            log(f"could not acquire inhibitor ({self.what}): {exc}")
            return False
        time.sleep(0.2)
        if self._proc.poll() is not None:
            log(f"inhibitor ({self.what}) exited immediately")
            self._proc = None
            return False
        log(f"inhibitor acquired: {self.what}")
        return True

    def release(self) -> None:
        if self._proc is None:
            return
        try:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        except OSError:
            pass
        finally:
            self._proc = None
            log(f"inhibitor released: {self.what}")

    def sync(self, wanted: bool) -> None:
        if wanted:
            self.acquire()
        else:
            self.release()


def list_inhibitors() -> str:
    if not which("systemd-inhibit"):
        return ""
    proc = run(["systemd-inhibit", "--list"], timeout=10)
    return proc.stdout or ""  # run() already collects text
