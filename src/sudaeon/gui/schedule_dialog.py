"""The window editor for the schedule tab.

Stock GTK only: seven day toggles, a start time and an end time dropdown in
15 minute steps.  Windows may cross midnight (for example 21:00 – 07:00).
"""

from __future__ import annotations

from typing import Any, Callable

from . import load_gtk
from .widgets import button, label, make_window, separator

Gtk, GLib, Gio, Adw = load_gtk()

HAS_ADW = Adw is not None

DAY_LABELS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
SHORT_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def time_slots(step_minutes: int = 15) -> list[str]:
    slots = []
    for minutes in range(0, 24 * 60, step_minutes):
        slots.append(f"{minutes // 60:02d}:{minutes % 60:02d}")
    return slots


class WindowDialog:
    """Modal editor for one schedule window."""

    def __init__(self, parent: Any, window: dict[str, Any] | None,
                 on_save: Callable[[dict[str, Any]], None]) -> None:
        self.parent = parent
        self.existing = dict(window) if window else None
        self.on_save = on_save
        self.slots = time_slots()
        self.window: Any = None
        self.day_buttons: list[Any] = []
        self.start_dropdown: Any = None
        self.end_dropdown: Any = None
        self.error_label: Any = None

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
        app = app_class(application_id="com.sudaeon.ScheduleEditor",
                        flags=Gio.ApplicationFlags.NON_UNIQUE)
        return app

    # ------------------------------------------------------------------

    def _build(self) -> None:
        self.window = make_window(self._app, title="Schedule Window", width= 520, height=-1,
                                  modal=True, parent=self.parent)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_top(18)
        content.set_margin_bottom(18)
        content.set_margin_start(18)
        content.set_margin_end(18)

        content.append(label("Days", bold=True))
        days_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        days_box.set_homogeneous(True)
        selected = set((self.existing or {}).get("days") or [0, 1, 2, 3, 4])
        for index, name in enumerate(SHORT_DAYS):
            toggle = Gtk.ToggleButton(label=name)
            toggle.set_active(index in selected)
            days_box.append(toggle)
            self.day_buttons.append(toggle)
        content.append(days_box)

        time_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        time_box.append(label("From"))
        self.start_dropdown = Gtk.DropDown.new_from_strings(self.slots)
        self.start_dropdown.set_selected(self._index((self.existing or {}).get("start", "21:00")))
        time_box.append(self.start_dropdown)
        time_box.append(label("to"))
        self.end_dropdown = Gtk.DropDown.new_from_strings(self.slots)
        self.end_dropdown.set_selected(self._index((self.existing or {}).get("end", "07:00")))
        time_box.append(self.end_dropdown)
        content.append(time_box)
        content.append(label("The window may cross midnight.", dim=True, wrap=True))

        self.error_label = label("", wrap=True)
        content.append(self.error_label)
        content.append(separator())

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons.set_halign(Gtk.Align.END)
        buttons.append(button("Cancel", on_click=lambda _b: (self.window.close(), self._app.quit())))
        buttons.append(button("Save", suggested=True, on_click=lambda _b: self._save()))
        content.append(buttons)

        if HAS_ADW:
            toolbar = Adw.ToolbarView()
            toolbar.add_top_bar(Adw.HeaderBar())
            toolbar.set_content(content)
            self.window.set_content(toolbar)
        else:
            self.window.set_child(content)

    def _index(self, value: str) -> int:
        return self.slots.index(value) if value in self.slots else 0

    def _save(self) -> None:
        days = [index for index, toggle in enumerate(self.day_buttons) if toggle.get_active()]
        if not days:
            self.error_label.set_text("Choose at least one day.")
            return
        start = self.slots[self.start_dropdown.get_selected()]
        end = self.slots[self.end_dropdown.get_selected()]
        if start == end:
            self.error_label.set_text("The start and end time are the same.")
            return
        self.on_save({"days": days, "start": start, "end": end})
        self.window.close()
        self._app.quit()
