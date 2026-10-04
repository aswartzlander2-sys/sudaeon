"""Enforcement schedule (quiet hours / bedtime windows).

A schedule is a list of windows.  Each window has a set of weekdays (0=Monday
... 6=Sunday) and a start/end time.  A window whose end time is not after its
start time spans midnight; ``days`` always refers to the day the window starts.

The same logic is implemented in C (``src/sudaeon/pam_sudaeon.c``) so the PAM
module can decide without a running daemon; both are covered by unit tests.
"""

from __future__ import annotations

from datetime import datetime, time
from typing import Any

DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
TIME_RE = r"^([01]\d|2[0-3]):([0-5]\d)$"

MODES = ("always", "enforce_during", "enforce_outside")
MODE_LABELS = {
    "always": "Always enforce policy",
    "enforce_during": "Enforce policy only during scheduled hours",
    "enforce_outside": "Enforce policy only outside scheduled hours",
}


def parse_time(text: str) -> time:
    hours, _, minutes = str(text).partition(":")
    return time(int(hours), int(minutes))


def format_time(value= time) -> str:
    return f"{value.hour:02d}:{value.minute:02d}"


def normalize_window(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    days_raw = raw.get("days")
    days: list[int] = []
    if isinstance(days_raw, (list, tuple)):
        for day in days_raw:
            try:
                number = int(day)
            except (TypeError, ValueError):
                continue
            if 0 <= number <= 6 and number not in days:
                days.append(number)
    if not days:
        days = [0, 1, 2, 3, 4, 5, 6]
    days.sort()

    def _time(value: Any, fallback: str) -> str:
        text = str(value or fallback)
        try:
            return format_time(parse_time(text))
        except (ValueError, TypeError):
            return fallback

    start = _time(raw.get("start"), "21:00")
    end = _time(raw.get("end"), "07:00")
    label = raw.get("label")
    window = {"days": days, "start": start, "end": end}
    if isinstance(label, str) and label.strip():
        window["label"] = label.strip()[:60]
    return window


def normalize(raw: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"mode": "always", "windows": []}
    if not isinstance(raw, dict):
        return result
    mode = raw.get("mode")
    if mode in MODES:
        result["mode"] = mode
    windows = []
    for item in raw.get("windows") or []:
        window = normalize_window(item)
        if window:
            windows.append(window)
    result["windows"] = windows[:32]
    if result["mode"] != "always" and not result["windows"]:
        result["mode"] = "always"
    return result


def validate(raw: Any) -> list[str]:
    if not isinstance(raw, dict):
        return ["Schedule is malformed."]
    problems = []
    if raw.get("mode") not in MODES:
        problems.append("Schedule mode is invalid.")
    windows = raw.get("windows")
    if windows is not None and not isinstance(windows, list):
        problems.append("Schedule windows must be a list.")
    return problems


def mode_of(schedule: Any) -> str:
    if isinstance(schedule, dict) and schedule.get("mode") in MODES:
        return schedule["mode"]
    return "always"


def windows_of(schedule: Any) -> list[dict[str, Any]]:
    if isinstance(schedule, dict) and isinstance(schedule.get("windows"), list):
        return [w for w in schedule["windows"] if isinstance(w, dict)]
    return []


def in_window(window: dict[str, Any], when: datetime) -> bool:
    start = parse_time(window.get("start", "00:00"))
    end = parse_time(window.get("end", "23:59"))
    days = list(window.get("days") or range(7))
    current = when.time()
    weekday = when.weekday()
    if start == end:
        return weekday in days            # all-day window
    if end > start:
        return weekday in days and start <= current < end
    # spans midnight: applies from `start` on the listed day until `end` next day
    if weekday in days and current >= start:
        return True
    previous_day = (weekday - 1) % 7
    return previous_day in days and current < end


def active_now(schedule: Any, when: datetime | None = None) -> bool:
    """Whether policy should be enforced at ``when``."""
    mode = mode_of(schedule)
    if mode == "always":
        return True
    when = when or datetime.now()
    windows = windows_of(schedule)
    inside = any(in_window(window, when) for window in windows)
    if mode == "enforce_during":
        return inside
    return not inside


def describe(schedule: Any) -> str:
    mode = mode_of(schedule)
    if mode == "always":
        return "at all times"
    windows = windows_of(schedule)
    if not windows:
        return "at all times"
    rendered = []
    for window in windows[:3]:
        days = _days_brief(window.get("days"))
        rendered.append(f"{days} {window.get('start')}-{window.get('end')}")
    if len(windows) > 3:
        rendered.append(f"+{len(windows) - 3} more")
    if mode == "enforce_during":
        return "during " + ", ".join(rendered)
    return "outside " + ", ".join(rendered)


def _days_brief(days: Any) -> str:
    try:
        values = sorted(int(day) for day in days)
    except (TypeError, ValueError):
        return "every day"
    if values == list(range(7)):
        return "every day"
    if values == [0, 1, 2, 3, 4]:
        return "weekdays"
    if values == [5, 6]:
        return "weekends"
    return "/".join(DAY_NAMES[day] for day in values if 0 <= day <= 6)


def make_window(days: list[int], start: str, end: str, label: str = "") -> dict[str, Any]:
    window = {"days": sorted({int(day) for day in days if 0 <= int(day) <= 6}),
              "start": start, "end": end}
    if label:
        window["label"] = label
    return window
