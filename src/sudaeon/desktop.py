"""Reading installed applications from the XDG desktop-entry database.

Sudaeon only needs to *list* and *override* entries, so this module is a small,
dependency free parser for ``.desktop`` files plus a simple launcher shim
mechanism used by :mod:`sudaeon.appgate`.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import paths

# Where desktop entries live, in the order the XDG specification uses.
SYSTEM_DIRS = (
    Path("/var/lib/flatpak/exports/share/applications"),
    Path("/usr/local/share/applications"),
    Path("/usr/share/applications"),
    Path("/var/lib/snapd/desktop/applications"),
    Path("/usr/share/gdm/applications"),
)
USER_DIRS = (
    Path("~/.local/share/applications"),
    Path("~/.local/share/flatpak/exports/share/applications"),
)

# Entries that must never be hidden or blocked: blocking them would make the
# desktop unusable or would lock the administrator out of the settings window.
PROTECTED_IDS = {
    "com.sudaeon.Sudaeon.desktop",
    "com.sudaeon.SudaeonPrompt.desktop",
    "gnome-shell.desktop",
    "org.gnome.Shell.desktop",
    "gnome-session-quit.desktop",
    "org.gnome.SessionManager.desktop",
    "gnome-control-center.desktop",
    "org.gnome.Settings.desktop",
    "gdm-launch-environment.desktop",
    "xdg-desktop-portal-gnome.desktop",
    "xdg-desktop-portal-gtk.desktop",
}


@dataclass
class DesktopEntry:
    id: str
    name: str
    path: Path
    exec_line: str = ""
    icon: str = ""
    comment: str = ""
    no_display: bool = False
    terminal: bool = False
    hidden: bool = False
    category: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def binary(self) -> str:
        """First word of the Exec line, if it looks like a program path."""
        try:
            words = shlex.split(self.exec_line.replace("%f", "").replace("%F", "")
                                .replace("%u", "").replace("%U", ""))
        except ValueError:
            words = [self.exec_line]
        for word in words:
            if word.startswith("/"):
                return word
            if word and not word.startswith("-") and "=" not in word:
                return word
        return ""

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "exec": self.exec_line,
                "icon": self.icon, "path": str(self.path),
                "binary": self.binary, "comment": self.comment}


def read_entry(path: Path) -> DesktopEntry | None:
    """Parse one ``.desktop`` file (``None`` when it is not usable)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    in_section = False
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_section = line.lower() == "[desktop entry]"
            continue
        if not in_section or not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("Name[") and "Name" not in values:
            continue
        if key.startswith("Name"):
            key = "Name"
        elif key.startswith("Comment"):
            key = "Comment"
        elif key.startswith("Exec"):
            key = "Exec"
        values[key] = value.strip()

    if not values.get("Name") or not values.get("Exec"):
        return None
    entry = DesktopEntry(
        id=path.name,
        name=values.get("Name", path.stem),
        path=path,
        exec_line=values.get("Exec", ""),
        icon=values.get("Icon", ""),
        comment=values.get("Comment", ""),
        no_display=values.get("NoDisplay", "").lower() == "true",
        terminal=values.get("Terminal", "").lower() == "true",
        hidden=values.get("Hidden", "").lower() == "true",
        category=(values.get("Categories", "") or "").split(";")[0].strip(),
    )
    entry.extra = values
    return entry


def search_dirs(*, include_user: bool = True, user_home: str | None = None) -> list[Path]:
    dirs = list(SYSTEM_DIRS)
    if include_user:
        home = user_home or os.path.expanduser("~")
        for template in USER_DIRS:
            dirs.append(Path(str(template).replace("~", home)))
    return [directory for directory in dirs if directory.exists()]


def installed(*, include_user: bool = True, include_hidden: bool = False,
              user_home: str | None = None) -> list[DesktopEntry]:
    """All visible desktop entries, de-duplicated by id (system dirs first)."""
    entries: dict[str, DesktopEntry] = {}
    for directory in search_dirs(include_user=include_user, user_home=user_home):
        try:
            children = sorted(directory.iterdir())
        except OSError:
            continue
        for path in children:
            if path.suffix != ".desktop" or path.name in entries:
                continue
            entry = read_entry(path)
            if entry is None:
                continue
            if entry.hidden:
                continue
            if entry.no_display and not include_hidden:
                continue
            entries[entry.id] = entry
    return sorted(entries.values(), key=lambda item: item.name.lower())


def find(identifier: str, **kwargs: Any) -> DesktopEntry | None:
    for entry in installed(**kwargs):
        if entry.id == identifier or entry.name == identifier:
            return entry
    return None


def categorized(entries: Iterable[DesktopEntry]) -> dict[str, list[DesktopEntry]]:
    groups: dict[str, list[DesktopEntry]] = {}
    for entry in entries:
        groups.setdefault(entry.category or "Other", []).append(entry)
    return groups


def is_protected(identifier: str) -> bool:
    return identifier in PROTECTED_IDS


def icon_file(icon_name: str, theme_dirs: Iterable[Path] | None = None) -> str | None:
    """Best effort lookup of an icon name in the usual hicolor directories."""
    if not icon_name:
        return None
    if icon_name.startswith("/") and Path(icon_name).exists():
        return icon_name
    layers = list(theme_dirs or ())
    if not layers:
        layers = [Path("/usr/share/icons/hicolor"), paths.ICON_HICOLOR,
                  Path("/usr/share/pixmaps")]
    for base in layers:
        if not base.exists():
            continue
        for size in ("256x256", "128x128", "64x64", "48x48", "scalable"):
            for sub in ("apps", "applications", "categories", ""):
                for suffix in (".svg", ".png", ".xpm"):
                    candidate = base / size / sub / f"{icon_name}{suffix}" if sub \
                        else base / size / f"{icon_name}{suffix}"
                    if candidate.exists():
                        return str(candidate)
        for suffix in (".svg", ".png"):
            candidate = base / f"{icon_name}{suffix}"
            if candidate.exists():
                return str(candidate)
    return None
