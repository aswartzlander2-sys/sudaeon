"""Small helpers shared by the Sudaeon windows.

Everything here is stock GTK 4 / libadwaita: no custom CSS, no custom drawing,
no bundled theme.  If libadwaita is missing the code degrades to plain GTK
widgets so the dashboard still opens on a minimal installation.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Sequence

from . import load_gtk

Gtk, GLib, Gio, Adw = load_gtk()

HAS_ADW = Adw is not None


def window_class():
    return Adw.ApplicationWindow if HAS_ADW else Gtk.ApplicationWindow


def application_class():
    return Adw.Application if HAS_ADW else Gtk.Application


def make_window(app, *, title: str = "Sudaeon", width: int = 820, height: int = 720,
                modal: bool = False, parent=None):
    window = window_class()(application=app)
    window.set_title(title)
    window.set_default_size(width, height)
    if modal:
        window.set_modal(True)
    if parent is not None:
        try:
            window.set_transient_for(parent)
        except Exception:
            pass
    return window


def header_bar(title: str = "Sudaeon", *, subtitle: str = "") -> Any:
    if HAS_ADW:
        bar = Adw.HeaderBar()
    else:
        bar = Gtk.HeaderBar()
        bar.set_show_title_buttons(True)
    label_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
    label = Gtk.Label(label=title)
    label.add_css_class("title-4" if HAS_ADW else "title")
    label.set_halign(Gtk.Align.CENTER)
    subtitle_label = Gtk.Label(label=subtitle)
    subtitle_label.add_css_class("dim-label")
    subtitle_label.add_css_class("caption")
    subtitle_label.set_halign(Gtk.Align.CENTER)
    subtitle_label.set_visible(bool(subtitle))
    label_box.append(label)
    label_box.append(subtitle_label)
    bar.set_title_widget(label_box)
    return bar


def clamp(child: Any, maximum: int = 720) -> Any:
    if HAS_ADW:
        wrapper = Adw.Clamp()
        wrapper.set_maximum_size(maximum)
        wrapper.set_child(child)
        return wrapper
    return child


def scrolled(child: Any) -> Any:
    scroller = Gtk.ScrolledWindow()
    scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    scroller.set_hexpand(True)
    scroller.set_vexpand(True)
    scroller.set_child(child)
    return scroller


def separator() -> Any:
    return Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)


def label(text: str, *, dim: bool = False, wrap: bool = False, bold: bool = False,
          css: str = "", xalign: float = 0.0, selectable: bool = False) -> Any:
    widget = Gtk.Label(label=text)
    widget.set_xalign(xalign)
    widget.set_wrap(wrap)
    widget.set_selectable(selectable)
    if dim:
        widget.add_css_class("dim-label")
    if bold:
        widget.add_css_class("heading")
    if css:
        for name in css.split():
            widget.add_css_class(name)
    return widget


def button(text: str, *, on_click: Callable[[Any], None] | None = None,
           suggested: bool = False, destructive: bool = False, flat: bool = False,
           pill: bool = False) -> Any:
    widget = Gtk.Button(label=text)
    if suggested:
        widget.add_css_class("suggested-action")
    if destructive:
        widget.add_css_class("destructive-action")
    if flat:
        widget.add_css_class("flat")
    if pill:
        widget.add_css_class("pill")
    if on_click is not None:
        widget.connect("clicked", on_click)
    return widget


def switch_row(title: str, *, subtitle: str = "", active: bool = True,
               on_toggle: Callable[[bool], None] | None = None,
               tooltip: str = "") -> Any:
    """A labelled switch row (libadwaita when available)."""
    if HAS_ADW:
        row = Adw.SwitchRow()
        row.set_title(title)
        if subtitle:
            row.set_subtitle(subtitle)
        row.set_active(bool(active))
    else:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        row.set_margin_top(6)
        row.set_margin_bottom(6)
        row.set_margin_start(12)
        row.set_margin_end(12)
        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        text_box.set_hexpand(True)
        text_box.append(label(title))
        if subtitle:
            text_box.append(label(subtitle, dim=True, wrap=True))
        row.append(text_box)
        toggle = Gtk.Switch()
        toggle.set_active(bool(active))
        toggle.set_valign(Gtk.Align.CENTER)
        row.append(toggle)
        toggle.connect("notify::active", lambda widget, _p: on_toggle(widget.get_active())
                       if on_toggle else None)
        return row
    if on_toggle is not None:
        row.connect("notify::active", lambda widget, _p: on_toggle(widget.get_active()))
    if tooltip:
        row.set_tooltip_text(tooltip)
    return row


def switch_active(row: Any) -> bool:
    return bool(row.get_active())


def set_switch_active(row: Any, value: bool) -> None:
    row.set_active(bool(value))


def combo_row(title: str, options: Sequence[str], *, selected: int = 0,
              subtitle: str = "", on_change: Callable[[int], None] | None = None) -> Any:
    if HAS_ADW:
        row = Adw.ComboRow()
        row.set_title(title)
        if subtitle:
            row.set_subtitle(subtitle)
        row.set_model(Gtk.StringList.new(list(options)))
        row.set_selected(int(selected))
        if on_change is not None:
            row.connect("notify::selected", lambda widget, _p: on_change(widget.get_selected()))
        return row
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    box.set_margin_top(6)
    box.set_margin_bottom(6)
    box.set_margin_start(12)
    box.set_margin_end(12)
    text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    text_box.set_hexpand(True)
    text_box.append(label(title))
    if subtitle:
        text_box.append(label(subtitle, dim=True, wrap=True))
    box.append(text_box)
    dropdown = Gtk.DropDown.new_from_strings(list(options))
    dropdown.set_selected(int(selected))
    if on_change is not None:
        dropdown.connect("notify::selected",
                         lambda widget, _p: on_change(widget.get_selected()))
    box.append(dropdown)

    class _ComboProxy:
        """Keeps the Adw.ComboRow call surface for the fallback widget."""

        def __init__(self, outer, inner):
            self._outer = outer
            self._inner = inner

        def get_selected(self):
            return self._inner.get_selected()

        def set_selected(self, index):
            self._inner.set_selected(int(index))

        def get_model(self):
            return self._inner.get_model()

        def set_model(self, model):
            self._inner.set_model(model)

        def set_sensitive(self, value):
            self._outer.set_sensitive(bool(value))

        def set_title(self, text):
            pass

        def set_subtitle(self, text):
            pass

        def set_visible(self, value):
            self._outer.set_visible(bool(value))

    return _ComboProxy(box, dropdown)


def combo_selected(row: Any) -> int:
    return int(row.get_selected())


def spin_row(title: str, *, value: int, lower: int, upper: int, step: int = 1,
             subtitle: str = "", on_change: Callable[[int], None] | None = None) -> Any:
    if HAS_ADW:
        adjustment = Gtk.Adjustment(value=float(value), lower=float(lower),
                                    upper=float(upper), step_increment=float(step))
        row = Adw.SpinRow(adjustment=adjustment, climb_rate=1, digits=0)
        row.set_title(title)
        if subtitle:
            row.set_subtitle(subtitle)
        if on_change is not None:
            row.connect("notify::value", lambda widget, _p: on_change(int(widget.get_value())))
        return row
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    box.set_margin_top(6)
    box.set_margin_bottom(6)
    box.set_margin_start(12)
    box.set_margin_end(12)
    text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    text_box.set_hexpand(True)
    text_box.append(label(title))
    if subtitle:
        text_box.append(label(subtitle, dim=True, wrap=True))
    box.append(text_box)
    spinner = Gtk.SpinButton.new_with_range(float(lower), float(upper), float(step))
    spinner.set_value(float(value))
    if on_change is not None:
        spinner.connect("value-changed", lambda widget: on_change(int(widget.get_value())))
    box.append(spinner)

    class _SpinProxy:
        def __init__(self, outer, inner):
            self._outer = outer
            self._inner = inner

        def get_value(self):
            return self._inner.get_value()

        def set_value(self, val):
            self._inner.set_value(float(val))

        def set_sensitive(self, val):
            self._outer.set_sensitive(bool(val))

        def set_visible(self, val):
            self._outer.set_visible(bool(val))

        def set_subtitle(self, text):
            pass

    return _SpinProxy(box, spinner)


def entry_row(title: str, *, text: str = "", on_change: Callable[[str], None] | None = None,
              subtitle: str = "") -> Any:
    if HAS_ADW:
        row = Adw.EntryRow()
        row.set_title(title)
        if subtitle:
            row.set_subtitle(subtitle)
        row.set_text(text)
        if on_change is not None:
            row.connect("changed", lambda widget: on_change(widget.get_text()))
        return row
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    box.set_margin_top(6)
    box.set_margin_bottom(6)
    box.set_margin_start(12)
    box.set_margin_end(12)
    text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    text_box.set_hexpand(True)
    text_box.append(label(title))
    if subtitle:
        text_box.append(label(subtitle, dim=True, wrap=True))
    box.append(text_box)
    entry = Gtk.Entry()
    entry.set_text(text)
    entry.set_hexpand(True)
    if on_change is not None:
        entry.connect("changed", lambda widget: on_change(widget.get_text()))
    box.append(entry)

    class _EntryProxy:
        def __init__(self, outer, inner):
            self._outer = outer
            self._inner = inner

        def get_text(self):
            return self._inner.get_text()

        def set_text(self, val):
            self._inner.set_text(val)

        def set_sensitive(self, val):
            self._outer.set_sensitive(bool(val))

        def set_visible(self, val):
            self._outer.set_visible(bool(val))

    return _EntryProxy(box, entry)


def action_row(title: str, *, subtitle: str = "", on_activate: Callable[[Any], None] | None = None,
               suffix: Any = None, activatable: bool = True) -> Any:
    if HAS_ADW:
        row = Adw.ActionRow()
        row.set_title(title)
        if subtitle:
            row.set_subtitle(subtitle)
        row.set_activatable(activatable and on_activate is not None)
        if suffix is not None:
            row.add_suffix(suffix)
        if on_activate is not None:
            row.connect("activated", on_activate)
        return row
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    row.set_margin_top(6)
    row.set_margin_bottom(6)
    row.set_margin_start(12)
    row.set_margin_end(12)
    text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    text_box.set_hexpand(True)
    text_box.append(label(title))
    if subtitle:
        text_box.append(label(subtitle, dim=True, wrap=True))
    row.append(text_box)
    if suffix is not None:
        row.append(suffix)
    if on_activate is not None:
        gesture = Gtk.GestureClick()
        gesture.connect("released", lambda *_a: on_activate(row))
        row.add_controller(gesture)
    return row


def group(title: str = "", description: str = "") -> Any:
    if HAS_ADW:
        widget = Adw.PreferencesGroup()
        if title:
            widget.set_title(title)
        if description:
            widget.set_description(description)
        return widget
    container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    container.set_margin_top(12)
    container.set_margin_bottom(6)
    container.set_margin_start(12)
    container.set_margin_end(12)
    if title:
        heading = label(title, bold=True)
        container.append(heading)
    if description:
        container.append(label(description, dim=True, wrap=True))
    return container


def group_add(target: Any, row: Any) -> None:
    if HAS_ADW:
        target.add(row)
    else:
        target.append(row)


def page() -> Any:
    if HAS_ADW:
        return Adw.PreferencesPage()
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    box.set_margin_top(12)
    box.set_margin_bottom(12)
    box.set_margin_start(12)
    box.set_margin_end(12)
    return box


def page_add(target: Any, child: Any) -> None:
    if HAS_ADW:
        target.add(child)
    else:
        target.append(child)


def message_dialog(parent, heading: str, body: str, *,
                   responses: Iterable[tuple[str, str]] = (("ok", "OK"),),
                   suggested: str = "", destructive: str = "",
                   on_response: Callable[[str], None] | None = None,
                   default: str = "") -> Any:
    """A native message dialog (Adw.MessageDialog or a plain window)."""
    if HAS_ADW:
        dialog = Adw.MessageDialog(transient_for=parent, heading=heading, body=body)
        dialog.set_modal(True)
        for identifier, text in responses:
            dialog.add_response(identifier, text)
            if identifier == suggested:
                dialog.set_response_appearance(identifier, Adw.ResponseAppearance.SUGGESTED)
            elif identifier == destructive:
                dialog.set_response_appearance(identifier, Adw.ResponseAppearance.DESTRUCTIVE)
            else:
                dialog.set_response_appearance(identifier, Adw.ResponseAppearance.DEFAULT)
        default_id = default or (responses[0][0] if responses else "ok")
        dialog.set_default_response(default_id)
        dialog.set_close_response(default_id)
        if on_response is not None:
            dialog.connect("response", lambda _d, identifier: on_response(identifier))
        dialog.present()
        return dialog

    window = Gtk.Window()
    window.set_title(heading)
    window.set_modal(True)
    window.set_default_size(420, -1)
    if parent is not None:
        try:
            window.set_transient_for(parent)
        except Exception:
            pass
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    box.set_margin_top(18)
    box.set_margin_bottom(18)
    box.set_margin_start(18)
    box.set_margin_end(18)
    box.append(label(heading, bold=True, wrap=True))
    box.append(label(body, wrap=True))
    buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    buttons.set_halign(Gtk.Align.END)
    for identifier, text in reversed(list(responses)):
        widget = button(text, suggested=(identifier == suggested),
                        destructive=(identifier == destructive))
        widget.connect("clicked", lambda _b, i=identifier: (
            window.close(), on_response(i) if on_response else None))
        buttons.append(widget)
    box.append(buttons)
    window.set_child(box)
    window.present()
    return window


def toast(overlay: Any, text: str) -> None:
    if HAS_ADW and isinstance(overlay, Adw.ToastOverlay):
        overlay.add_toast(Adw.Toast(title=text))
    else:
        print(text)


def status_page(title: str, description: str, icon: str = "dialog-password-symbolic",
                child: Any = None) -> Any:
    if HAS_ADW:
        page_widget = Adw.StatusPage()
        page_widget.set_title(title)
        page_widget.set_description(description)
        page_widget.set_icon_name(icon)
        if child is not None:
            page_widget.set_child(child)
        return page_widget
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    box.set_valign(Gtk.Align.CENTER)
    box.append(label(title, bold=True, xalign=0.5))
    box.append(label(description, dim=True, wrap=True, xalign=0.5))
    if child is not None:
        box.append(child)
    return box


def expire_on_idle(callback: Callable[[], None], seconds: int) -> int:
    return GLib.timeout_add_seconds(max(1, seconds), callback)


def idle(callback: Callable[[], Any]) -> None:
    GLib.idle_add(callback)
