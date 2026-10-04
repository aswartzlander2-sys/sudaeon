"""GTK4/libadwaita user interface for Sudaeon.

The look and feel is deliberately stock Ubuntu/GNOME: stock Adwaita widgets,
stock icon names, system fonts and the default theme.  Sudaeon adds no CSS of
its own.
"""

from __future__ import annotations

import os
import sys

APP_ID = "com.sudaeon.Sudaeon"
PROMPT_APP_ID = "com.sudaeon.Permission"


def load_gtk():
    """Import GTK and libadwaita, raising a helpful error when unavailable."""
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        from gi.repository import GLib, Gio, Gtk  # noqa: F401
        adw = None
        try:
            gi.require_version("Adw", "1")
            from gi.repository import Adw
            adw = Adw
        except (ValueError, ImportError):
            adw = None
        return Gtk, GLib, Gio, adw
    except Exception as exc:  # pragma: no cover - depends on the system
        raise RuntimeError(
            "the Sudaeon dashboard needs GTK 4 and libadwaita\n"
            "install them with: sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1"
        ) from exc


def gui_available() -> bool:
    try:
        load_gtk()
        return True
    except RuntimeError:
        return False


__all__ = ["load_gtk", "gui_available", "APP_ID", "PROMPT_APP_ID"]
