"""The "Add an application" picker for the Applications tab.

Stock GTK only: a search entry on top of a plain :class:`Gtk.ListBox` with one
row per installed desktop application.  Application control is a speed bump,
so the list deliberately shows *applications*, never raw binaries - blocking a
binary is not something the policy can express.
"""

from __future__ import annotations

from typing import Any, Callable

from . import load_gtk
from .widgets import button, label, make_window, separator

Gtk, GLib, Gio, Adw = load_gtk()

HAS_ADW = Adw is not None

#: Long lists stay responsive; the search entry filters this many entries.
MAX_ROWS = 400


class AppPicker:
    """Modal list of installed applications.

    ``on_pick`` receives the dictionary shape used by the policy
    (``id``, ``name``, ``exec``, ``icon`` ...) and the picker closes itself.
    """

    def __init__(self, parent: Any, on_pick: Callable[[dict[str, Any]], None]) -> None:
        self.parent = parent
        self.on_pick = on_pick
        self.window: Any = None
        self.search: Any = None
        self.listbox: Any = None
        self.empty_label: Any = None
        self._apps: list[dict[str, Any]] = []
        self._app: Any = None

    # ------------------------------------------------------------------

    def present(self) -> None:
        app = self._application()
        self._app = app

        def on_activate(_app) -> None:
            self._build()
            self.window.present()

        app.connect("activate", on_activate)
        try:
            app.run([])
        except Exception:
            pass

    def _application(self) -> Any:
        app_class = Adw.Application if HAS_ADW else Gtk.Application
        return app_class(application_id="com.sudaeon.AppPicker",
                         flags=Gio.ApplicationFlags.NON_UNIQUE)

    # ------------------------------------------------------------------

    def _build(self) -> None:
        self.window = make_window(self._app, title="Add an Application", width=560,
                                  height=640, modal=True, parent=self.parent)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_top(18)
        content.set_margin_bottom(18)
        content.set_margin_start(18)
        content.set_margin_end(18)

        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text("Search applications")
        self.search.connect("search-changed", lambda _entry: self._fill())
        content.append(self.search)

        self.empty_label = label("No applications were found on this computer.",
                                 dim=True, wrap=True)

        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        self.listbox.add_css_class("boxed-list")
        self.listbox.connect("row-activated", self._on_row_activated)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_vexpand(True)
        scrolled.set_child(self.listbox)
        content.append(scrolled)
        content.append(separator())
        content.append(label("Applications that keep the desktop running cannot be "
                             "blocked, and this list is not a sandbox: see the note "
                             "on the Applications page.", dim=True, wrap=True))

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons.set_halign(Gtk.Align.END)
        buttons.append(button("Cancel", on_click=lambda _b: self._close()))
        content.append(buttons)

        if HAS_ADW:
            toolbar = Adw.ToolbarView()
            toolbar.add_top_bar(Adw.HeaderBar())
            toolbar.set_content(content)
            self.window.set_content(toolbar)
        else:
            self.window.set_child(content)

        self._apps = self._load_apps()
        self._fill()

    def _load_apps(self) -> list[dict[str, Any]]:
        try:
            from .. import appgate
            return appgate.installed_apps()
        except Exception:
            return []

    # ------------------------------------------------------------------

    def _matches(self, entry: dict[str, Any], needle: str) -> bool:
        if not needle:
            return True
        haystack = " ".join((str(entry.get("name") or ""), str(entry.get("id") or ""),
                             str(entry.get("comment") or ""))).lower()
        return needle in haystack

    def _fill(self) -> None:
        child = self.listbox.get_first_child()
        while child is not None:
            following = child.get_next_sibling()
            self.listbox.remove(child)
            child = following

        needle = (self.search.get_text() if self.search is not None else "").strip().lower()
        shown = 0
        for entry in self._apps:
            if not self._matches(entry, needle):
                continue
            self.listbox.append(self._make_row(entry))
            shown += 1
            if shown >= MAX_ROWS:
                break
        if shown == 0:
            self.listbox.append(self._make_message_row(
                "Nothing matched your search." if needle else
                "No applications were found on this computer."))

    def _make_row(self, entry: dict[str, Any]) -> Any:
        row = Gtk.ListBoxRow()
        row.set_activatable(True)
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        box.set_margin_start(8)
        box.set_margin_end(8)

        icon = entry.get("icon") or ""
        image = None
        if icon:
            try:
                from .. import desktop
                path = desktop.icon_file(str(icon))
            except Exception:
                path = None
            try:
                image = Gtk.Image.new_from_file(path) if path else \
                    Gtk.Image.new_from_icon_name(str(icon))
            except Exception:
                image = None
        if image is None:
            image = Gtk.Image.new_from_icon_name("application-x-executable")
        image.set_pixel_size(32)
        box.append(image)

        texts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        texts.set_hexpand(True)
        name = Gtk.Label(label=str(entry.get("name") or entry.get("id") or "?"))
        name.set_xalign(0.0)
        name.add_css_class("heading")
        texts.append(name)
        detail = str(entry.get("comment") or entry.get("id") or "")
        if detail:
            texts.append(label(detail, dim=True, wrap=True))
        box.append(texts)

        row.set_child(box)
        row.sudaeon_entry = entry  # type: ignore[attr-defined]
        return row

    @staticmethod
    def _make_message_row(message: str) -> Any:
        row = Gtk.ListBoxRow()
        row.set_activatable(False)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        box.append(label(message, dim=True, wrap=True))
        row.set_child(box)
        return row

    # ------------------------------------------------------------------

    def _on_row_activated(self, _listbox, row) -> None:
        entry = getattr(row, "sudaeon_entry", None)
        if not isinstance(entry, dict):
            return
        name = str(entry.get("id") or entry.get("name") or "")
        if not name:
            return
        try:
            self.on_pick(entry)
        finally:
            self._close()

    def _close(self) -> None:
        try:
            if self.window is not None:
                self.window.close()
        finally:
            if self._app is not None:
                self._app.quit()
