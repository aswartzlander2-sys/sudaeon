"""The Sudaeon Permission Manager.

Two windows, exactly as specified:

``Sudaeon Permission Manager``
    "Please Enter the Master Password" with a password box.

``Sudaeon Permission Manager - Access Denied``
    "The Password Entered was Incorrect" with a **Retry** button.

The password is verified through the setuid ``sudaeon-chkpwd`` helper, so this
dialog shares rate limiting and auditing with the terminal prompts.  Three
attempts are allowed (configurable); after that the action is refused.
"""

from __future__ import annotations

import threading
from typing import Any, Callable

from .. import prompt
from . import load_gtk
from .widgets import (HAS_ADW, button, label, make_window, message_dialog, separator)

Gtk, GLib, Gio, Adw = load_gtk()

TITLE = prompt.TITLE_PERMISSION
TITLE_DENIED = prompt.TITLE_DENIED
TEXT = prompt.TEXT_PERMISSION
TEXT_INCORRECT = prompt.TEXT_INCORRECT


class _State:
    def __init__(self, attempts: int) -> None:
        self.attempts = max(1, attempts)
        self.used = 0
        self.ok = False
        self.reason = "cancelled"
        self.password = ""


def _verify_async(password: str, callback: Callable[[bool, int, str], None]) -> None:
    def worker() -> None:
        ok, code, message = prompt.verify(password)
        GLib.idle_add(callback, ok, code, message)
    threading.Thread(target=worker, name="sudaeon-verify", daemon=True).start()


def _window_content(title: str, body: str, *, entry: Any = None) -> Any:
    if HAS_ADW:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)
        heading = label(title, bold=True, wrap=True, xalign=0.5)
        heading.add_css_class("title-3")
        box.append(heading)
        box.append(label(body, wrap=True, xalign=0.5))
        if entry is not None:
            box.append(entry)
        return box
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    box.set_margin_top(18)
    box.set_margin_bottom(18)
    box.set_margin_start(18)
    box.set_margin_end(18)
    box.append(label(title, bold=True, wrap=True))
    box.append(label(body, wrap=True))
    if entry is not None:
        box.append(entry)
    return box


def ask(verb: str = "", *, attempts: int = prompt.DEFAULT_ATTEMPTS,
        title: str = TEXT, text: str = TEXT, parent: Any = None) -> prompt.PromptResult:
    """Show the permission dialog and return the outcome.

    Works both standalone (an extra application is created) and from inside the
    dashboard or the session agent (a nested main loop is used).
    """
    Gtk, GLib, Gio, Adw = load_gtk()
    app_class = Adw.Application if HAS_ADW else Gtk.Application
    app = app_class(application_id="com.sudaeon.Permission",
                    flags=Gio.ApplicationFlags.NON_UNIQUE)
    state = _State(attempts)
    windows: dict[str, Any] = {}

    def finish() -> None:
        try:
            app.quit()
        except Exception:
            pass

    def show_denied(reason: str, retry: bool) -> None:
        if "denied" in windows:
            windows["denied"].close()
        if reason == "locked":
            body = "Too many incorrect attempts. Please wait before trying again."
            retry = False
        else:
            body = TEXT_INCORRECT
        responses = [("retry", "Retry")] if retry else []
        responses.append(("close", "Close"))
        windows["denied"] = message_dialog(
            windows.get("password"), TITLE_DENIED, body,
            responses=responses, suggested="retry" if retry else "close",
            default="retry" if retry else "close",
            on_response=lambda identifier: (
                (windows["denied"].close(), show_password())
                if identifier == "retry" else (finish(), None)),
        )

    def submit(password: str) -> None:
        state.used += 1

        def after(ok: bool, code: int, message: str) -> None:
            if ok:
                state.ok = True
                state.reason = "ok"
                state.password = password
                if windows.get("password") is not None:
                    windows["password"].close()
                finish()
                return
            if code == 3:
                state.reason = "locked"
                show_denied("locked", retry=False)
                return
            if code != 1:
                state.reason = "error"
                if windows.get("password") is not None:
                    windows["password"].close()
                message_dialog(windows.get("password"), TITLE_DENIED,
                               message or "The master password could not be verified.",
                               responses=[("close", "Close")], default="close",
                               on_response=lambda _i: finish())
                return
            state.reason = "too-many" if state.used >= state.attempts else "incorrect"
            show_denied(state.reason, retry=state.used < state.attempts)

        _verify_async(password, after)

    def show_password() -> None:
        if "password" in windows and windows["password"] is not None:
            try:
                windows["password"].close()
            except Exception:
                pass
        window = make_window(app, title=TITLE, width= 420, height=-1, modal=True,
                             parent=parent)
        entry = Gtk.PasswordEntry()
        entry.set_show_peek_icon(True)
        entry.set_activates_default(True)
        if verb:
            body = f"{text}\n\n{verb.capitalize()}"
        else:
            body = text
        content = _window_content(TITLE, body, entry=entry)
        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons.set_halign(Gtk.Align.END)
        cancel = button("Cancel", on_click=lambda _b: (window.close(), finish()))
        unlock = button("Unlock", suggested=True,
                        on_click=lambda _b: submit(entry.get_text()))
        buttons.append(cancel)
        buttons.append(unlock)
        content.append(separator())
        content.append(buttons)
        window.set_child(content)
        entry.connect("activate", lambda _e: submit(entry.get_text()))
        window.present()
        entry.grab_focus()
        windows["password"] = window

    def on_activate(_app) -> None:
        show_password()

    app.connect("activate", on_activate)
    try:
        app.run([])
    except Exception:
        pass
    if state.ok:
        return prompt.PromptResult(True, "ok", state.used, state.password)
    return prompt.PromptResult(False, state.reason, state.used)


def ask_new_password(*, title: str = "New Master Password", parent: Any = None,
                     minimum: int = 8) -> str | None:
    """Ask for a *new* password twice; returns it when both entries match."""
    from .. import crypto
    app_class = Adw.Application if HAS_ADW else Gtk.Application
    app = app_class(application_id="com.sudaeon.Permission",
                    flags=Gio.ApplicationFlags.NON_UNIQUE)
    result: dict[str, str | None] = {"value": None}

    def on_activate(_app) -> None:
        window = make_window(app, title=TITLE, width= 460, height=-1, modal=True, parent=parent)
        first = Gtk.PasswordEntry()
        first.set_show_peek_icon(True)
        second = Gtk.PasswordEntry()
        second.set_show_peek_icon(True)
        first.set_placeholder_text(title)
        second.set_placeholder_text("Repeat the password")
        entries = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        entries.append(first)
        entries.append(second)
        hint = label("", dim=True, wrap=True)
        content = _window_content(TITLE, title, entry=entries)
        content.append(hint)
        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons.set_halign(Gtk.Align.END)

        def accept() -> None:
            value = first.get_text()
            if value != second.get_text():
                hint.set_text("The two passwords are different.")
                return
            problems = crypto.password_problems(value, minimum=minimum)
            if problems:
                hint.set_text(" ".join(problems))
                return
            result["value"] = value
            window.close()
            app.quit()

        buttons.append(button("Cancel", on_click=lambda _b: (window.close(), app.quit())))
        buttons.append(button("Continue", suggested=True, on_click=lambda _b: accept()))
        content.append(separator())
        content.append(buttons)
        window.set_child(content)
        first.connect("activate", lambda _e: second.grab_focus())
        second.connect("activate", lambda _e: accept())
        window.present()
        first.grab_focus()

    app.connect("activate", on_activate)
    try:
        app.run([])
    except Exception:
        pass
    return result["value"]


def ask_recovery(*, attempts: int = prompt.DEFAULT_ATTEMPTS, parent: Any = None) -> str | None:
    """Ask for a recovery key (used by the password reset flow)."""
    from ..gui import widgets
    result: dict[str, str | None] = {"key": None}
    app_class = Adw.Application if HAS_ADW else Gtk.Application
    app = app_class(application_id="com.sudaeon.Permission",
                    flags=Gio.ApplicationFlags.NON_UNIQUE)

    def on_activate(_app) -> None:
        window = make_window(app, title=TITLE, width= 460, height=-1, modal=True, parent=parent)
        entry = Gtk.Entry()
        entry.set_placeholder_text("XXXX-XXXX-XXXX-XXXX-XXXX")
        content = _window_content(TITLE, "Please Enter the Recovery Key", entry=entry)
        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons.set_halign(Gtk.Align.END)

        def accept() -> None:
            result["key"] = entry.get_text()
            window.close()
            app.quit()

        buttons.append(button("Cancel", on_click=lambda _b: (window.close(), app.quit())))
        buttons.append(button("Continue", suggested=True, on_click=lambda _b: accept()))
        content.append(separator())
        content.append(buttons)
        window.set_child(content)
        window.present()
        entry.grab_focus()

    app.connect("activate", on_activate)
    try:
        app.run([])
    except Exception:
        pass
    return result["key"]
