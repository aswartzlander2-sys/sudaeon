"""The "Reset the master password" dialog for the Advanced tab.

This is the recovery path: the master password is gone, so the user either
pastes the recovery key that was printed during setup or - for an
administrator - resets the vault with administrative rights.  Either way a new
master password is chosen and a *new* recovery key is generated; the old key
stops working.

Stock GTK only: a few entries and two buttons.
"""

from __future__ import annotations

from typing import Any, Callable

from . import load_gtk
from .widgets import button, label, make_window, separator

Gtk, GLib, Gio, Adw = load_gtk()

HAS_ADW = Adw is not None


class ResetPasswordDialog:
    """Modal dialog that resets the master password.

    ``on_done`` is called with ``(new_password, recovery_key)`` after the
    helper has written the new verifier records.
    """

    def __init__(self, parent: Any,
                 on_done: Callable[[str, str], None]) -> None:
        self.parent = parent
        self.on_done = on_done
        self.window: Any = None
        self.recovery_entry: Any = None
        self.password_entry: Any = None
        self.confirm_entry: Any = None
        self.error_label: Any = None
        self.buttons: list[Any] = []
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
        return app_class(application_id="com.sudaeon.ResetPassword",
                         flags=Gio.ApplicationFlags.NON_UNIQUE)

    # ------------------------------------------------------------------

    def _build(self) -> None:
        self.window = make_window(self._app, title="Reset Master Password",
                                  width=520, height=-1, modal=True,
                                  parent=self.parent)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_top(18)
        content.set_margin_bottom(18)
        content.set_margin_start(18)
        content.set_margin_end(18)

        content.append(label("Reset the master password", bold=True))
        content.append(label(
            "Enter the recovery key that was shown when Sudaeon was set up. "
            "Administrators can leave it empty to reset with administrative "
            "rights. A new recovery key is generated either way.",
            dim=True, wrap=True))
        content.append(separator())

        content.append(label("Recovery key", bold=True))
        self.recovery_entry = Gtk.Entry()
        self.recovery_entry.set_placeholder_text("XXXXX-XXXXX-XXXXX-XXXXX")
        self.recovery_entry.set_hexpand(True)
        content.append(self.recovery_entry)
        content.append(label("Leave empty when you no longer have the key.",
                             dim=True, wrap=True))

        content.append(label("New master password", bold=True))
        self.password_entry = Gtk.PasswordEntry()
        try:
            self.password_entry.set_show_peek_icon(True)
        except Exception:
            pass
        content.append(self.password_entry)

        content.append(label("Retype the new master password", bold=True))
        self.confirm_entry = Gtk.PasswordEntry()
        try:
            self.confirm_entry.set_show_peek_icon(True)
        except Exception:
            pass
        content.append(self.confirm_entry)
        content.append(label("At least 8 characters. Longer passphrases are "
                             "better than short passwords.", dim=True, wrap=True))

        self.error_label = label("", wrap=True)
        content.append(self.error_label)
        content.append(separator())

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons.set_halign(Gtk.Align.END)
        buttons.append(button("Cancel", on_click=lambda _b: self._close()))
        reset_button = button("Reset Password", suggested=True,
                              on_click=lambda _b: self._submit())
        buttons.append(reset_button)
        self.buttons.append(reset_button)
        content.append(buttons)

        if HAS_ADW:
            toolbar = Adw.ToolbarView()
            toolbar.add_top_bar(Adw.HeaderBar())
            toolbar.set_content(content)
            self.window.set_content(toolbar)
        else:
            self.window.set_child(content)

    # ------------------------------------------------------------------

    def _text(self, entry: Any) -> str:
        try:
            return str(entry.get_text())
        except Exception:
            return ""

    def _fail(self, message: str) -> None:
        self.error_label.set_text(message)
        for widget in self.buttons:
            widget.set_sensitive(True)

    def _set_busy(self) -> None:
        self.error_label.set_text("")
        for widget in self.buttons:
            widget.set_sensitive(False)

    def _submit(self) -> None:
        from .. import crypto
        from ..util import username_of
        from .. import privilege

        recovery_key = crypto.normalize_recovery_key(self._text(self.recovery_entry))
        password = self._text(self.password_entry)
        confirm = self._text(self.confirm_entry)

        if password != confirm:
            self._fail("The passwords do not match.")
            return
        problems = crypto.password_problems(password, username=username_of() or "")
        if problems:
            self._fail(" ".join(problems))
            return

        payload: dict[str, Any] = {"new": password, "new_password_confirm": confirm}
        if recovery_key:
            payload["recovery_key"] = recovery_key
        else:
            payload["force"] = True

        self._set_busy()
        try:
            result = privilege.call_helper_with_master("reset-master", "", payload,
                                                       timeout=180.0)
        except privilege.PrivilegeError as exc:
            self._fail(str(exc))
            return
        if not result.ok:
            self._fail(result.error or "the master password could not be reset")
            return

        new_key = str((result.data or {}).get("recovery_key") or "")
        self._close()
        try:
            self.on_done(password, new_key)
        except Exception:
            pass

    def _close(self) -> None:
        try:
            if self.window is not None:
                self.window.close()
        finally:
            if self._app is not None:
                self._app.quit()
