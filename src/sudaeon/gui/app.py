"""Sudaeon's GUI entry points.

Five modes, all built from stock GTK4 and libadwaita widgets:

``dashboard``
    The main window (Administrators only): the "Use Sudaeon" switch, the tabbed
    enforcement settings, the user manager and the maintenance actions.

``setup``
    The first-run wizard.  It asks for the master password twice, provisions
    the verifier/vault through the privileged helper and shows the recovery
    key exactly once.

``permission`` / ``prompt``
    The "Sudaeon Permission Manager" dialog used by other programs.

``prefs``
    A small preferences/About window for the launcher and the desktop entry.

The command line entry point lives in :mod:`sudaeon.cli`; this module only
knows how to put windows on the screen.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable

MODES = ("dashboard", "setup", "permission", "prompt", "prefs", "install-blocked")

PAGES = ("power", "enforcement", "users", "schedule", "applications", "logs", "advanced")


# ---------------------------------------------------------------------------
# small helpers shared by the modes
# ---------------------------------------------------------------------------

def _crypto_policy_message() -> str:
    return "the Sudaeon graphical interface needs GTK 4 and libadwaita"


def already_installed(parent: Any = None) -> None:
    """The duplicate-install popup (also used by the command line)."""
    from ..installer import ALREADY_INSTALLED_MESSAGE
    from .widgets import message_dialog

    app = _standalone_application()
    shown = {"done": False}

    def on_activate(_app) -> None:
        shown["done"] = True
        message_dialog(parent, "Sudaeon", ALREADY_INSTALLED_MESSAGE,
                       responses=[("ok", "Close")], default="ok",
                       on_response=lambda _i: _app.quit())

    app.connect("activate", on_activate)
    try:
        app.run([])
    except Exception:
        pass


def _standalone_application(identifier: str = "com.sudaeon.SudaeonPrompt") -> Any:
    from . import load_gtk

    Gtk, _GLib, Gio, Adw = load_gtk()
    app_class = Adw.Application if Adw is not None else Gtk.Application
    return app_class(application_id=identifier, flags=Gio.ApplicationFlags.NON_UNIQUE)


def admin_ok(policy: dict[str, Any]) -> bool:
    from .. import config
    from ..util import invoking_uid, username_of

    name = username_of(invoking_uid()) or ""
    return bool(name) and config.can_open_dashboard(policy, name)


# ---------------------------------------------------------------------------
# the first-run wizard
# ---------------------------------------------------------------------------

class SetupWizard:
    """Ask for the master password, install/provision, show the recovery key."""

    def __init__(self) -> None:
        from . import load_gtk

        self.Gtk, self.GLib, self.Gio, self.Adw = load_gtk()
        self.HAS_ADW = self.Adw is not None
        self.app: Any = None
        self.window: Any = None
        self.stack: Any = None
        self.password_entry: Any = None
        self.confirm_entry: Any = None
        self.strength_label: Any = None
        self.error_label: Any = None
        self.recovery_label: Any = None
        self.saved_check: Any = None
        self.continue_button: Any = None
        self.finish_button: Any = None
        self.password = ""
        self.recovery_key = ""
        self.installed_now = False
        self.failed = False

    # -- lifecycle ------------------------------------------------------

    def run(self) -> int:
        app = _standalone_application("com.sudaeon.Setup")
        self.app = app

        def on_activate(_app) -> None:
            self._build()
            self.window.present()

        app.connect("activate", on_activate)
        try:
            app.run([])
        except Exception:
            pass
        return 1 if self.failed else 0

    # -- build ----------------------------------------------------------

    def _build(self) -> None:
        from .. import version
        from .widgets import label, separator

        Gtk = self.Gtk
        self.window = self._make_window(title=f"Sudaeon {version.APP_VERSION} Setup",
                                        width=560)
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)

        # page 1: the master password
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        page.append(label("Welcome to Sudaeon", bold=True))
        page.append(label(
            "Choose the master password. It unlocks the dashboard and is asked "
            "for whenever a blocked action needs permission. It cannot be "
            "recovered: a recovery key will be shown in the next step.", wrap=True))
        page.append(separator())
        page.append(label("Master password", bold=True))
        self.password_entry = Gtk.PasswordEntry()
        self.password_entry.set_show_peek_icon(True)
        self.password_entry.connect("changed", lambda _e: self._refresh_strength())
        page.append(self.password_entry)
        page.append(label("Retype the master password", bold=True))
        self.confirm_entry = Gtk.PasswordEntry()
        self.confirm_entry.set_show_peek_icon(True)
        page.append(self.confirm_entry)
        self.strength_label = label("", dim=True, wrap=True)
        page.append(self.strength_label)
        self.error_label = label("", wrap=True)
        page.append(self.error_label)
        page.append(separator())
        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons.set_halign(Gtk.Align.END)
        buttons.append(self._button("Quit", self._quit))
        self.continue_button = self._button("Continue", self._start, suggested=True)
        buttons.append(self.continue_button)
        page.append(buttons)
        self.stack.add_named(self._wrap(page), "password")

        # page 2: the recovery key
        page2 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        page2.append(label("Save the recovery key", bold=True))
        page2.append(label(
            "This key is the only way back in when the master password is "
            "forgotten. It is shown once and is not stored anywhere.", wrap=True))
        self.recovery_label = label("", wrap=True, selectable=True, bold=True)
        page2.append(self.recovery_label)
        self.saved_check = Gtk.CheckButton(label="I have written down the recovery key")
        self.saved_check.connect("toggled", lambda _c: self._refresh_finish())
        page2.append(self.saved_check)
        page2.append(separator())
        buttons2 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons2.set_halign(Gtk.Align.END)
        self.finish_button = self._button("Finish", self._finish, suggested=True)
        self.finish_button.set_sensitive(False)
        buttons2.append(self.finish_button)
        page2.append(buttons2)
        self.stack.add_named(self._wrap(page2), "recovery")

        self._set_page_content(self.stack)

    def _make_window(self, *, title: str, width: int) -> Any:
        from .widgets import make_window

        return make_window(self.app, title=title, width=width, height=-1, modal=False)

    def _wrap(self, child: Any) -> Any:
        Gtk = self.Gtk
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)
        box.append(child)
        return box

    def _set_page_content(self, content: Any) -> None:
        if self.HAS_ADW:
            toolbar = self.Adw.ToolbarView()
            toolbar.add_top_bar(self.Adw.HeaderBar())
            toolbar.set_content(content)
            self.window.set_content(toolbar)
        else:
            self.window.set_child(content)

    def _button(self, text: str, on_click: Callable[[Any], None], *,
                suggested: bool = False) -> Any:
        from .widgets import button

        return button(text, on_click=on_click, suggested=suggested)

    # -- behaviour ------------------------------------------------------

    def _entry_text(self, entry: Any) -> str:
        try:
            return str(entry.get_text())
        except Exception:
            return ""

    def _refresh_strength(self) -> None:
        from .. import crypto

        password = self._entry_text(self.password_entry)
        if not password:
            self.strength_label.set_text("")
            return
        score = crypto.password_score(password)
        self.strength_label.set_text(f"Strength: {crypto.strength_label(score)}")

    def _refresh_finish(self) -> None:
        self.finish_button.set_sensitive(bool(self.saved_check.get_active()))

    def _quit(self, _widget: Any = None) -> None:
        self._close()

    def _close(self) -> None:
        try:
            if self.window is not None:
                self.window.close()
        finally:
            if self.app is not None:
                self.app.quit()

    def _start(self, _widget: Any = None) -> None:
        from .. import crypto
        from ..util import invoking_uid, username_of

        password = self._entry_text(self.password_entry)
        confirm = self._entry_text(self.confirm_entry)
        if password != confirm:
            self.error_label.set_text("The passwords do not match.")
            return
        problems = crypto.password_problems(password,
                                            username=username_of(invoking_uid()) or "")
        if problems:
            self.error_label.set_text(" ".join(problems))
            return

        self.error_label.set_text("Setting up Sudaeon…")
        for widget in (self.continue_button,):
            widget.set_sensitive(False)

        ok, message, recovery = self._provision(password)
        if not ok:
            self.failed = True
            self.continue_button.set_sensitive(True)
            self.error_label.set_text(message or "Sudaeon could not be installed.")
            return

        self.password = password
        self.recovery_key = recovery
        self.recovery_label.set_text(crypto.recovery_key_display(recovery) or recovery)
        self.error_label.set_text("")
        self.stack.set_visible_child_name("recovery")

    def _provision(self, password: str) -> tuple[bool, str, str]:
        """Install (first run) or provision the master password.  Root helper."""
        from .. import installstate, privilege, vault

        master_exists = vault.read_master_record() is not None
        payload: dict[str, Any] = {"user": _current_user()}
        try:
            if installstate.is_installed() and master_exists:
                # Nothing to do: the password already exists (guard on re-runs).
                return True, "", ""
            if installstate.is_installed():
                result = privilege.call_helper_with_master(
                    "provision-master", password, {"enable": True}, timeout=600.0)
            else:
                result = privilege.call_helper_with_master(
                    "install", password, payload, timeout=900.0)
                self.installed_now = result.ok
        except privilege.PrivilegeError as exc:
            return False, str(exc), ""
        if not result.ok:
            return False, result.error or "the helper refused the request", ""
        data = result.data or {}
        return True, result.message, str(data.get("recovery_key") or "")

    def _finish(self, _widget: Any = None) -> None:
        self._close()


def _current_user() -> str:
    from ..util import invoking_uid, username_of

    return username_of(invoking_uid()) or ""


# ---------------------------------------------------------------------------
# preferences
# ---------------------------------------------------------------------------

class PreferencesWindow:
    """The small window behind the launcher's "Preferences" entry."""

    def __init__(self) -> None:
        from . import load_gtk

        self.Gtk, self.GLib, self.Gio, self.Adw = load_gtk()
        self.HAS_ADW = self.Adw is not None
        self.app: Any = None
        self.window: Any = None

    def run(self) -> int:
        app = _standalone_application("com.sudaeon.Preferences")
        self.app = app

        def on_activate(_app) -> None:
            self._build()
            self.window.present()

        app.connect("activate", on_activate)
        try:
            app.run([])
        except Exception:
            pass
        return 0

    def _build(self) -> None:
        from .. import installstate, vault, version
        from .widgets import action_row, group, group_add, label, make_window, separator

        Gtk = self.Gtk
        self.window = make_window(self.app, title="Sudaeon Preferences", width=520,
                                  height=-1, modal=False)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_top(18)
        content.set_margin_bottom(18)
        content.set_margin_start(18)
        content.set_margin_end(18)

        content.append(label(f"Sudaeon {version.APP_VERSION}", bold=True))
        details = installstate.installation_details()
        policy = vault.load_policy() or {}
        state = "installed" if details.get("installed") else "not installed"
        content.append(label(f"{state} · master password "
                             f"{'set' if details.get('master_verifier_exists') else 'not set'}",
                             dim=True, wrap=True))
        content.append(separator())

        actions = group("Actions")
        group_add(actions, action_row("Open the dashboard",
                                      subtitle="Administrators only",
                                      on_activate=lambda _r: self._open_dashboard()))
        group_add(actions, action_row("Run the doctor",
                                      subtitle="Check PAM, polkit, sudoers and the service",
                                      on_activate=lambda _r: self._doctor()))
        content.append(actions)

        if not policy:
            content.append(label("Sudaeon is not configured yet. Run the setup "
                                 "wizard from the application menu.", dim=True, wrap=True))

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons.set_halign(Gtk.Align.END)
        from .widgets import button
        buttons.append(button("Close", on_click=lambda _b: self._close()))
        content.append(separator())
        content.append(buttons)

        if self.HAS_ADW:
            toolbar = self.Adw.ToolbarView()
            toolbar.add_top_bar(self.Adw.HeaderBar())
            toolbar.set_content(content)
            self.window.set_content(toolbar)
        else:
            self.window.set_child(content)

    def _open_dashboard(self) -> None:
        self._close()
        main(["dashboard"])

    def _doctor(self) -> None:
        from .. import diagnostics
        from .widgets import message_dialog

        try:
            report = diagnostics.run_checks()
            text = diagnostics.format_report(report)
        except Exception as exc:  # pragma: no cover - defensive
            text = f"the doctor could not run: {exc}"
        message_dialog(self.window, "Sudaeon Doctor", text,
                       responses=[("ok", "Close")], default="ok",
                       on_response=lambda _i: None)

    def _close(self) -> None:
        try:
            if self.window is not None:
                self.window.close()
        finally:
            if self.app is not None:
                self.app.quit()


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------

def run_dashboard(page: str = "") -> int:
    """Open the main window.  Returns a process exit status."""
    from .. import config, vault
    from . import load_gtk
    from .widgets import message_dialog

    if not _display_available():
        print("Sudaeon: no graphical display was found; run this from a desktop session",
              file=sys.stderr)
        return 3

    Gtk, _GLib, Gio, Adw = load_gtk()
    app_class = Adw.Application if Adw is not None else Gtk.Application
    app = app_class(application_id="com.sudaeon.Sudaeon",
                    flags=Gio.ApplicationFlags.NON_UNIQUE)
    state: dict[str, Any] = {"status": 0}

    def refuse(heading: str, body: str) -> None:
        state["status"] = 4
        message_dialog(None, heading, body, responses=[("ok", "Close")], default="ok",
                       on_response=lambda _i: app.quit())

    def on_activate(_app) -> None:
        from .. import installstate
        if not installstate.is_installed():
            refuse("Sudaeon", "Sudaeon is not installed on this computer.")
            return
        policy = vault.load_policy()
        if policy is None:
            refuse("Sudaeon", "Sudaeon is installed but has no policy yet. "
                              "Run the setup wizard.")
            return
        if vault.read_master_record() is None:
            wizard = SetupWizard()
            if wizard.run() != 0:
                app.quit()
                return
            policy = vault.load_policy() or policy
        if not admin_ok(policy):
            state["status"] = 5
            message_dialog(None, "Sudaeon",
                           "Only Sudaeon Administrators can open the dashboard. "
                           "Ask an administrator to change your role.",
                           responses=[("ok", "Close")], default="ok",
                           on_response=lambda _i: app.quit())
            return
        from .dashboard import Dashboard
        window = Dashboard(app)
        if not window.open():
            state["status"] = 1
            return
        if page in PAGES:
            window.show_page(page)

    app.connect("activate", on_activate)
    try:
        app.run([])
    except Exception as exc:  # pragma: no cover - depends on the session
        print(f"Sudaeon: could not open the dashboard: {exc}", file=sys.stderr)
        return 1
    return state["status"]


def _display_available() -> bool:
    import os

    return bool(os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY"))


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------

USAGE = """usage: sudaeon-gui [MODE] [options]

Modes:
  dashboard        open the dashboard (default, Administrators only)
  setup            run the first-run wizard
  permission       ask for the master password (used by other programs)
  prompt           alias of permission
  prefs            open the preferences window

Options:
  --page NAME      dashboard page: power, enforcement, users, schedule,
                   applications, logs, advanced
  --verb TEXT      what the permission dialog is asking for
  --title TEXT     permission dialog title
  --text TEXT      permission dialog body text
  --attempts N     attempts before the permission dialog refuses
  --json           print the permission result as JSON on stdout
"""


def parse_argv(argv: list[str]) -> tuple[str, dict[str, Any]]:
    mode = "dashboard"
    options: dict[str, Any] = {"page": "", "verb": "", "title": "", "text": "",
                               "attempts": None, "json": False}
    index = 0
    while index < len(argv):
        item = argv[index]
        if item in ("-h", "--help"):
            options["help"] = True
            index += 1
            continue
        if item in MODES:
            mode = item
            index += 1
            continue
        if item == "--json":
            options["json"] = True
            index += 1
            continue
        value = argv[index + 1] if index + 1 < len(argv) else ""
        if item == "--page":
            options["page"] = value
            index += 2
            continue
        if item == "--verb":
            options["verb"] = value
            index += 2
            continue
        if item == "--title":
            options["title"] = value
            index += 2
            continue
        if item == "--text":
            options["text"] = value
            index += 2
            continue
        if item == "--attempts":
            try:
                options["attempts"] = int(value)
            except ValueError:
                options["attempts"] = None
            index += 2
            continue
        index += 1
    return mode, options


def run_permission(options: dict[str, Any]) -> int:
    """The standalone permission dialog (``permission``/``prompt`` modes)."""
    from .. import prompt

    if not _display_available() or not gui_available():
        print("Sudaeon: no graphical display was found", file=sys.stderr)
        return 3
    from . import prompt_window

    attempts = options.get("attempts") or prompt.DEFAULT_ATTEMPTS
    result = prompt_window.ask(options.get("verb") or "",
                               attempts=int(attempts),
                               title=options.get("title") or prompt.TITLE_PERMISSION,
                               text=options.get("text") or prompt.TEXT_PERMISSION)
    if options.get("json"):
        print(json.dumps({"ok": result.ok, "reason": result.reason,
                          "attempts": result.attempts}))
    return 0 if result.ok else 1


def gui_available() -> bool:
    from . import gui_available as _gui_available

    return _gui_available()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    mode, options = parse_argv(argv)
    if options.get("help"):
        print(USAGE)
        return 0
    if not gui_available():
        print(f"Sudaeon: {_crypto_policy_message()}", file=sys.stderr)
        print("Install them with: sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1",
              file=sys.stderr)
        return 3

    if mode in ("permission", "prompt"):
        return run_permission(options)
    if mode == "setup":
        return SetupWizard().run()
    if mode == "prefs":
        return PreferencesWindow().run()
    if mode == "install-blocked":
        already_installed()
        return 0
    return run_dashboard(str(options.get("page") or ""))


if __name__ == "__main__":  # pragma: no cover - manual entry point
    raise SystemExit(main())
