"""The Sudaeon dashboard.

Layout (top to bottom), matching the requested design:

    [ header: title | tabs switcher | menu | Apply ]
    ---------------------------------------------------
     Use Sudaeon                                    (o)
     <status line>
    ---------------------------------------------------   <- horizontal line
     Power | Enforcement | Users | Schedule | Applications | Logs | Advanced
     ...the selected tab...
    ---------------------------------------------------
     footer: dirty indicator + Apply / Revert

Switching "Use Sudaeon" off greys out everything below the line.  Administrators
only: the window is not opened for other accounts.
"""

from __future__ import annotations

import copy
import os
import time
from typing import Any, Callable

from .. import audit, config, paths, privilege, users, vault
from ..util import log, username_of, invoking_uid
from . import load_gtk
from .widgets import (HAS_ADW, action_row, button, clamp, combo_row, entry_row, group,
                      group_add, label, make_window, message_dialog, page, page_add,
                      scrolled, separator, set_switch_active, spin_row, switch_row, toast)
from . import prompt_window

Gtk, GLib, Gio, Adw = load_gtk()

ROLE_ORDER = (config.ROLE_ADMIN, config.ROLE_EXEMPT, config.ROLE_REGULAR)


class Dashboard:
    def __init__(self, app: Any) -> None:
        self.app = app
        self.user = username_of(invoking_uid()) or "?"
        self.policy: dict[str, Any] = config.default_policy()
        self.original: dict[str, Any] = config.default_policy()
        self.password = ""
        self.unlocked_until = 0.0
        self.window: Any = None
        self.stack: Any = None
        self.switcher: Any = None
        self.apply_button: Any = None
        self.revert_button: Any = None
        self.status_label: Any = None
        self.dirty_label: Any = None
        self.banner: Any = None
        self.rows: dict[str, Any] = {}
        self.role_combos: dict[str, Any] = {}
        self.schedule_windows: list[dict[str, Any]] = []
        self.audit_list: Any = None
        self.apps_list: Any = None
        self.window_rows: list[Any] = []
        self.app_rows: list[Any] = []
        self.windows_group: Any = None
        self.apps_group: Any = None
        self.users_group: Any = None
        self.master_group: Any = None
        self.audit_group: Any = None
        self.toast_overlay: Any = None
        self.last_error = ""

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def load(self) -> bool:
        result = privilege.call_helper("get-policy", prefer_pkexec=True)
        if not result.ok:
            loaded = vault.load_policy()
            if loaded is None:
                self.last_error = result.error or "Sudaeon is not installed"
                return False
            self.policy = loaded
        else:
            self.policy = config.normalize_policy((result.data or {}).get("policy") or {})
        self.original = copy.deepcopy(self.policy)
        self.schedule_windows = [dict(item)
                                 for item in (self.policy.get("schedule", {}).get("windows") or [])]
        return True

    def unlock(self, *, force: bool = False) -> bool:
        """Ask for the master password (once per unlock window)."""
        if not force and self.password and time.monotonic() < self.unlocked_until:
            return True
        minutes = int(self.policy.get("advanced", {}).get("unlock_minutes", 5) or 5)
        attempts = int(self.policy.get("enforcement", {}).get("terminal_max_attempts", 3))
        result = prompt_window.ask("Open the Sudaeon dashboard", parent=self.window,
                                   attempts=attempts)
        if not result.ok or not result.password:
            self.password = ""
            return False
        self.password = result.password
        self.unlocked_until = time.monotonic() + max(0, minutes) * 60
        return True

    # ------------------------------------------------------------------
    # building
    # ------------------------------------------------------------------

    def build(self) -> Any:
        self.window = make_window(self.app, title="Sudaeon", width=920, height=760)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.set_margin_start(12)
        content.set_margin_end(12)
        content.append(self._build_global_section())
        content.append(separator())
        content.append(self._build_stack())
        content.append(separator())
        content.append(self._build_footer())

        header = self._build_header()
        if HAS_ADW:
            toolbar = Adw.ToolbarView()
            toolbar.add_top_bar(header)
            toolbar.set_content(content)
            overlay = Adw.ToastOverlay()
            overlay.set_child(toolbar)
            self.window.set_content(overlay)
            self.toast_overlay = overlay
        else:
            self.window.set_titlebar(header)
            self.window.set_child(content)
            self.toast_overlay = None

        self._sync_sensitivity()
        self._refresh_status()
        return self.window

    def open(self) -> bool:
        """Load the policy, unlock, then show the window."""
        if not self.load():
            message_dialog(None, "Sudaeon", self.last_error or
                           "Sudaeon is not available on this computer.",
                           responses=[("ok", "Close")], default="ok",
                           on_response=lambda _i: self.app.quit())
            return False
        if not self.unlock():
            return False
        self.build()
        self.window.present()
        return True

    def _build_header(self) -> Any:
        if HAS_ADW:
            bar = Adw.HeaderBar()
        else:
            bar = Gtk.HeaderBar()
        title = label("Sudaeon", bold=True)
        switcher = Gtk.StackSwitcher()
        self.switcher = switcher
        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        title_box.set_halign(Gtk.Align.CENTER)
        title_box.append(title)
        title_box.append(switcher)
        bar.set_title_widget(title_box)
        bar.pack_start(self._build_menu_button())
        self.revert_button = button("Revert", on_click=lambda _b: self.revert_changes(), flat=True)
        self.apply_button = button("Apply", on_click=lambda _b: self.apply_changes(), suggested=True)
        self.revert_button.set_sensitive(False)
        self.apply_button.set_sensitive(False)
        bar.pack_end(self.apply_button)
        bar.pack_end(self.revert_button)
        return bar

    def _build_menu_button(self) -> Any:
        menu = Gio.Menu()
        menu.append("Diagnostics", "win.doctor")
        menu.append("Documentation", "win.docs")
        menu.append("Open a Terminal", "win.terminal")
        menu.append("About Sudaeon", "win.about")
        menu.append("Lock the Dashboard", "win.lock")
        menu.append("Remove Sudaeon…", "win.uninstall")
        widget = Gtk.MenuButton()
        widget.set_icon_name("open-menu-symbolic")
        widget.set_menu_model(menu)
        widget.set_tooltip_text("Main Menu")
        actions = {
            "doctor": self.on_doctor,
            "docs": self.on_docs,
            "terminal": self.on_terminal,
            "about": self.on_about,
            "lock": self.on_lock,
            "uninstall": self.on_uninstall,
        }
        for name, callback in actions.items():
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", lambda _a, _p, cb=callback: cb())
            self.app.add_action(action)
        return widget

    def _build_global_section(self) -> Any:
        container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        if HAS_ADW:
            box = Adw.PreferencesGroup()
        else:
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.rows["enabled"] = switch_row(
            "Use Sudaeon", subtitle="Enforce the policy below on this computer",
            active=bool(self.policy.get("enabled")),
            on_toggle=self.on_enabled_toggled)
        group_add(box, self.rows["enabled"])
        self.status_label = label("", dim=True, wrap=True)
        self.status_label.set_margin_start(12)
        self.status_label.set_margin_end(12)
        self.status_label.set_margin_bottom(6)
        container.append(box)
        container.append(self.status_label)
        if HAS_ADW and hasattr(Adw, "Banner"):
            self.banner = Adw.Banner()
            self.banner.set_revealed(False)
            self.banner.set_button_label("Turn on")
            self.banner.connect("button-clicked",
                                lambda _b: set_switch_active(self.rows["enabled"], True))
            container.append(self.banner)
        return container

    def _build_stack(self) -> Any:
        stack = Gtk.Stack()
        stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        stack.set_vexpand(True)
        stack.set_hexpand(True)
        self.stack = stack
        self._build_power_page(stack)
        self._build_enforcement_page(stack)
        self._build_users_page(stack)
        self._build_schedule_page(stack)
        self._build_apps_page(stack)
        self._build_logs_page(stack)
        self._build_advanced_page(stack)
        if self.switcher is not None:
            self.switcher.set_stack(stack)
        return scrolled(clamp(stack))

    def _build_footer(self) -> Any:
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.dirty_label = label("", dim=True)
        self.dirty_label.set_hexpand(True)
        box.append(self.dirty_label)
        box.append(self.revert_button)
        box.append(self.apply_button)
        return box

    # ------------------------------------------------------------------
    # pages
    # ------------------------------------------------------------------

    def _add_page(self, stack: Any, name: str, title: str, widget: Any) -> Any:
        stack.add_titled(widget, name, title)
        return widget

    def _build_power_page(self, stack: Any) -> None:
        widget = page()
        power = group("System Power",
                      "Turning an option off means it needs the master password.")
        for key in ("reboot", "poweroff", "halt", "suspend", "hibernate", "hybrid_sleep",
                    "suspend_then_hibernate", "kexec", "soft_reboot"):
            spec = config.action(key)
            self.rows[key] = switch_row(
                spec.label.replace("Allow ", ""),
                subtitle=_power_hint(key),
                active=config.action_allowed(self.policy, key),
                on_toggle=lambda value, k=key: self.set_action(k, value))
            group_add(power, self.rows[key])
        page_add(widget, power)

        button_group = group("Power Button",
                             "What happens when the power button is pressed while policy is on.")
        modes = list(config.POWER_BUTTON_MODES)
        self.rows["power_button"] = combo_row(
            "Allow Power Button to Bypass",
            [config.POWER_BUTTON_LABELS[mode] for mode in modes],
            selected=modes.index(self.policy.get("power_button", "require_master")),
            subtitle="Disable ignores the button, Require Master Password asks first",
            on_change=lambda index: self.set_power_button(modes[index]))
        group_add(button_group, self.rows["power_button"])
        page_add(widget, button_group)

        session = group("Session",
                        "Enforced through the GNOME session settings (dconf lockdown).")
        for key in ("log_out", "lock_screen", "switch_user", "command_line", "printing",
                    "save_to_disk"):
            spec = config.action(key)
            self.rows[key] = switch_row(
                spec.label.replace("Allow ", ""),
                subtitle="",
                active=config.action_allowed(self.policy, key),
                on_toggle=lambda value, k=key: self.set_action(k, value))
            group_add(session, self.rows[key])
        page_add(widget, session)

        note = group("")
        group_add(note, action_row(
            "Blocking logout or user switching",
            subtitle="A blocked session action also requires the master password. Enable "
                     "“Exempt administrators from policy” in Advanced if you need "
                     "unattended scripts to run."))
        page_add(widget, note)
        self._add_page(stack, "power", "Power", widget)

    def _build_enforcement_page(self, stack: Any) -> None:
        widget = page()
        terminal = group(
            "Enforcement",
            "Extra protection for administrative work. The master password is asked for "
            "in addition to the normal user password.")
        for key in ("sudo", "user_management", "polkit_admin", "package_management",
                    "removable_media", "root_login"):
            spec = config.action(key)
            self.rows[key] = switch_row(
                spec.label.replace("Block ", ""),
                subtitle=spec.description,
                active=not config.action_allowed(self.policy, key),
                on_toggle=lambda value, k=key: self.set_action(k, not value))
            group_add(terminal, self.rows[key])
        page_add(widget, terminal)

        terminal_options = group("Terminal Prompts")
        enforcement = self.policy.get("enforcement", {})
        self.rows["terminal_max_attempts"] = spin_row(
            "Attempts before the terminal gives up",
            value=int(enforcement.get("terminal_max_attempts", 3)), lower=1, upper=10,
            subtitle="After this many wrong master passwords the command is refused",
            on_change=lambda value: self.set_enforcement("terminal_max_attempts", value))
        group_add(terminal_options, self.rows["terminal_max_attempts"])
        self.rows["terminal_prompt_text"] = entry_row(
            "Terminal prompt",
            text=str(enforcement.get("terminal_prompt_text",
                                     "Please Enter the Master Password:")),
            subtitle="Shown after the [Sudaeon] prefix, for example: "
                     "[Sudaeon]: Please Enter the Master Password:",
            on_change=lambda value: self.set_enforcement("terminal_prompt_text", value))
        group_add(terminal_options, self.rows["terminal_prompt_text"])
        self.rows["lockout_seconds"] = spin_row(
            "Lock out after repeated failures (seconds)",
            value=int(enforcement.get("lockout_seconds", 30)), lower=0, upper=900, step=5,
            subtitle="Applies to terminals, the dashboard and the permission dialogs",
            on_change=lambda value: self.set_enforcement("lockout_seconds", value))
        group_add(terminal_options, self.rows["lockout_seconds"])
        self.rows["audit_attempts"] = switch_row(
            "Log every master password attempt", subtitle="",
            active=bool(enforcement.get("audit_attempts", True)),
            on_toggle=lambda value: self.set_enforcement("audit_attempts", bool(value)))
        group_add(terminal_options, self.rows["audit_attempts"])
        self.rows["notify"] = switch_row(
            "Show desktop notifications", subtitle="",
            active=bool(enforcement.get("notify", True)),
            on_toggle=lambda value: self.set_enforcement("notify", bool(value)))
        group_add(terminal_options, self.rows["notify"])
        self.rows["fail_closed"] = switch_row(
            "Fail closed when Sudaeon cannot verify",
            subtitle="Refuse privileged actions if the master verifier is unreadable",
            active=bool(enforcement.get("fail_closed", True)),
            on_toggle=lambda value: self.set_enforcement("fail_closed", bool(value)))
        group_add(terminal_options, self.rows["fail_closed"])
        self.rows["lock_gnome_settings"] = switch_row(
            "Lock the GNOME session settings",
            subtitle="Stops the session options from being changed with gsettings/dconf",
            active=bool(enforcement.get("lock_gnome_settings", True)),
            on_toggle=lambda value: self.set_enforcement("lock_gnome_settings", bool(value)))
        group_add(terminal_options, self.rows["lock_gnome_settings"])
        page_add(widget, terminal_options)

        note = group("")
        group_add(note, action_row(
            "How terminal enforcement works",
            subtitle="pam_sudaeon.so is inserted into the sudo, su, pkexec and passwd "
                     "service files. It asks for the master password before the user "
                     "password, prints “The Password Entered was Incorrect” on a wrong "
                     "entry and “The Password was incorrect too many times.” after "
                     f"{int(enforcement.get('terminal_max_attempts', 3))} attempts."))
        page_add(widget, note)
        self._add_page(stack, "enforcement", "Enforcement", widget)

    def _build_users_page(self, stack: Any) -> None:
        widget = page()
        entries = users.list_users(self.policy)
        counts = users.summarize_roles(self.policy)
        info = group("Accounts on this computer",
                     f"{counts['total']} accounts · {counts[config.ROLE_ADMIN]} administrators · "
                     f"{counts[config.ROLE_EXEMPT]} exempt · {counts[config.ROLE_REGULAR]} regular")
        self.users_group = info
        for entry in entries:
            role = entry.get("role") or config.role_for(self.policy, entry["name"])
            combo = combo_row("", [config.ROLE_LABELS[item] for item in ROLE_ORDER],
                              selected=ROLE_ORDER.index(role) if role in ROLE_ORDER else 2,
                              on_change=lambda index, name=entry["name"]:
                              self.set_role(name, ROLE_ORDER[index]))
            self.role_combos[entry["name"]] = combo
            subtitle_parts = [f"uid {entry['uid']}"]
            if entry.get("full_name"):
                subtitle_parts.append(entry["full_name"])
            if entry.get("sudoer"):
                subtitle_parts.append("in sudo group")
            if entry.get("logged_in"):
                subtitle_parts.append("logged in")
            if entry.get("explicit_role"):
                subtitle_parts.append("set here")
            row = action_row(entry["name"], subtitle=" · ".join(subtitle_parts), suffix=combo)
            group_add(info, row)
        page_add(widget, info)

        help_group = group("Roles")
        for role in ROLE_ORDER:
            group_add(help_group, action_row(config.ROLE_LABELS[role],
                                             subtitle=config.ROLE_DESCRIPTIONS[role],
                                             activatable=False))
        page_add(widget, help_group)

        refresh = group("")
        group_add(refresh, action_row(
            "Sudaeon applies to every account on this computer",
            subtitle="The setting here follows the account, not the login session. "
                     "Members of the sudo group are administrators by default (change "
                     "that in Advanced)."))
        group_add(refresh, action_row("Refresh the list",
                                      subtitle="Re-read accounts and sessions",
                                      on_activate=lambda _r: self.reload_users()))
        page_add(widget, refresh)
        self._add_page(stack, "users", "Users", widget)

    def _build_schedule_page(self, stack: Any) -> None:
        widget = page()
        modes = list(config.schedule.MODES)
        schedule = self.policy.get("schedule", {})
        basic = group("Schedule", "Restrict when the policy is enforced "
                                  "(for example only in the evening).")
        self.rows["schedule_mode"] = combo_row(
            "When to enforce", [config.schedule.MODE_LABELS[mode] for mode in modes],
            selected=modes.index(schedule.get("mode", "always")),
            on_change=lambda index: self.set_schedule_mode(modes[index]))
        group_add(basic, self.rows["schedule_mode"])
        self.windows_group = group("Windows")
        self._render_windows()
        page_add(widget, basic)
        page_add(widget, self.windows_group)
        actions = group("")
        group_add(actions, action_row("Add a window", subtitle="Choose days and times",
                                      on_activate=lambda _r: self.edit_window(None)))
        page_add(widget, actions)
        self._add_page(stack, "schedule", "Schedule", widget)

    def _build_apps_page(self, stack: Any) -> None:
        widget = page()
        basic = group("Application Control",
                      "Blocked applications ask for the master password before they start.")
        self.rows["applications_enabled"] = switch_row(
            "Enable application control", subtitle="",
            active=bool(self.policy.get("applications", {}).get("enabled")),
            on_toggle=lambda value: self.set_applications_enabled(bool(value)))
        group_add(basic, self.rows["applications_enabled"])
        page_add(widget, basic)

        self.apps_group = group("Blocked Applications")
        self._render_apps()
        page_add(widget, self.apps_group)
        act = group("")
        group_add(act, action_row("Add an application…",
                                  subtitle="Pick from the installed applications",
                                  on_activate=lambda _r: self.add_application()))
        page_add(widget, act)

        note = group("Limitations")
        group_add(note, action_row(
            "Application control is a speed bump",
            subtitle="Programs started outside the launcher (scripts, terminals) can "
                     "bypass it. Use the power, session and sudo settings for hard limits.",
            activatable=False))
        page_add(widget, note)
        self._add_page(stack, "applications", "Applications", widget)

    def _build_logs_page(self, stack: Any) -> None:
        widget = page()
        header = group("Audit Log", "Every master password attempt and policy change.")
        group_add(header, action_row("Refresh", subtitle="Reload the newest entries",
                                     on_activate=lambda _r: self.reload_audit()))
        group_add(header, action_row("Clear the log…",
                                     subtitle="Requires the master password",
                                     on_activate=lambda _r: self.clear_audit()))
        page_add(widget, header)
        self.audit_group = group("Recent Activity")
        self.audit_list = Gtk.ListBox()
        self.audit_list.set_selection_mode(Gtk.SelectionMode.NONE)
        group_add(self.audit_group, self.audit_list)
        page_add(widget, self.audit_group)
        self._add_page(stack, "logs", "Logs", widget)
        self.reload_audit()

    def _build_advanced_page(self, stack: Any) -> None:
        widget = page()
        behaviour = group("Behaviour")
        advanced = self.policy.get("advanced", {})
        user_settings = self.policy.get("users", {})
        self.rows["exempt_admins"] = switch_row(
            "Exempt administrators from policy",
            subtitle="Administrators keep dashboard access but are not restricted",
            active=bool(user_settings.get("exempt_admins", False)),
            on_toggle=lambda value: self.set_user_setting("exempt_admins", bool(value)))
        group_add(behaviour, self.rows["exempt_admins"])
        self.rows["auto_admin_sudo_group"] = switch_row(
            "Treat members of the sudo group as administrators",
            subtitle="They can become root anyway, so Sudaeon shows them the dashboard",
            active=bool(user_settings.get("auto_admin_sudo_group", True)),
            on_toggle=lambda value: self.set_user_setting("auto_admin_sudo_group", bool(value)))
        group_add(behaviour, self.rows["auto_admin_sudo_group"])
        self.rows["unlock_minutes"] = spin_row(
            "Keep the dashboard unlocked for (minutes)", value=int(advanced.get("unlock_minutes", 5)),
            lower=0, upper=60,
            subtitle="Zero asks for the master password on every change",
            on_change=lambda value: self.set_advanced("unlock_minutes", value))
        group_add(behaviour, self.rows["unlock_minutes"])
        page_add(widget, behaviour)

        master = group("Master Password", "Applies to every account on this computer.")
        group_add(master, action_row("Change the master password…",
                                     subtitle="Requires the current password",
                                     on_activate=lambda _r: self.change_password()))
        group_add(master, action_row("Show the recovery key…",
                                     subtitle="Requires the master password",
                                     on_activate=lambda _r: self.show_recovery_key()))
        group_add(master, action_row("Create a new recovery key…",
                                     subtitle="The old key stops working",
                                     on_activate=lambda _r: self.regenerate_recovery_key()))
        group_add(master, action_row("Reset the master password…",
                                     subtitle="Use the recovery key, or root access",
                                     on_activate=lambda _r: self.reset_password()))
        self.master_group = master
        page_add(widget, master)

        maintenance = group("Maintenance")
        group_add(maintenance, action_row("Run diagnostics",
                                          subtitle="Check that enforcement is wired up",
                                          on_activate=lambda _r: self.on_doctor()))
        group_add(maintenance, action_row("Repair enforcement files",
                                          subtitle="Rewrite PAM, polkit, sudoers and dconf "
                                                   "files from the policy",
                                          on_activate=lambda _r: self.repair()))
        group_add(maintenance, action_row("Restart the sentinel",
                                          subtitle="The background service that guards the "
                                                   "power button",
                                          on_activate=lambda _r: self.restart_sentinel()))
        vault_info = vault.vault_info()
        group_add(maintenance, action_row(
            "Encrypted vault",
            subtitle=f"{vault_info.get('path', '?')} · {vault_info.get('bytes', 0)} bytes · "
                     f"{vault_info.get('kdf', '?')} n={vault_info.get('kdf_n', '?')}",
            activatable=False))
        page_add(widget, maintenance)

        danger = group("Danger Zone")
        group_add(danger, action_row("Restore the default policy…",
                                     subtitle="Keeps the master password",
                                     on_activate=lambda _r: self.restore_defaults()))
        group_add(danger, action_row("Remove Sudaeon…",
                                     subtitle="Removes enforcement from this computer",
                                     on_activate=lambda _r: self.on_uninstall()))
        page_add(widget, danger)
        self._add_page(stack, "advanced", "Advanced", widget)

    # ------------------------------------------------------------------
    # state handling
    # ------------------------------------------------------------------

    def show_page(self, name: str) -> bool:
        """Select one of the tab pages by name (used by the command line)."""
        if self.stack is None or not name:
            return False
        try:
            return bool(self.stack.set_visible_child_name(name))
        except Exception:
            return False

    def mark_dirty(self) -> None:
        dirty = self.is_dirty()
        if self.dirty_label is not None:
            self.dirty_label.set_text("Unsaved changes" if dirty else "")
        if self.apply_button is not None:
            self.apply_button.set_sensitive(dirty)
        if self.revert_button is not None:
            self.revert_button.set_sensitive(dirty)

    def is_dirty(self) -> bool:
        return self.policy != self.original

    def set_action(self, key: str, value: bool) -> None:
        config.set_action(self.policy, key, value)
        self.policy.setdefault("applications", {})
        config.stamp_policy(self.policy)
        self.mark_dirty()

    def set_power_button(self, mode: str) -> None:
        if mode in config.POWER_BUTTON_MODES:
            self.policy["power_button"] = mode
            config.stamp_policy(self.policy)
            self.mark_dirty()

    def set_enforcement(self, key: str, value: Any) -> None:
        self.policy.setdefault("enforcement", {})[key] = value
        config.stamp_policy(self.policy)
        self.mark_dirty()

    def set_advanced(self, key: str, value: Any) -> None:
        self.policy.setdefault("advanced", {})[key] = value
        config.stamp_policy(self.policy)
        self.mark_dirty()

    def set_user_setting(self, key: str, value: Any) -> None:
        self.policy.setdefault("users", {})[key] = value
        config.stamp_policy(self.policy)
        self.mark_dirty()

    def set_role(self, name: str, role: str) -> None:
        if role not in config.ROLES:
            return
        config.set_role(self.policy, name, role)
        config.stamp_policy(self.policy)
        self.mark_dirty()

    def set_schedule_mode(self, mode: str) -> None:
        self.policy.setdefault("schedule", {})["mode"] = mode
        self.policy["schedule"]["windows"] = self.schedule_windows
        config.stamp_policy(self.policy)
        self.mark_dirty()

    def set_applications_enabled(self, value: bool) -> None:
        self.policy.setdefault("applications", {})["enabled"] = bool(value)
        config.stamp_policy(self.policy)
        self.mark_dirty()

    def on_enabled_toggled(self, value: bool) -> None:
        self.policy["enabled"] = bool(value)
        config.stamp_policy(self.policy)
        self._sync_sensitivity()
        self._refresh_status()
        self.mark_dirty()

    def _sync_sensitivity(self) -> None:
        enabled = bool(self.policy.get("enabled"))
        for widget in (self.stack, self.switcher):
            if widget is not None:
                widget.set_sensitive(enabled)
        if self.banner is not None:
            self.banner.set_revealed(not enabled)
        if getattr(self, "window", None) is not None:
            self.window.set_title("Sudaeon" if enabled else "Sudaeon (off)")

    def _refresh_status(self) -> None:
        if self.status_label is None:
            return
        text = config.summary(self.policy)
        if not self.policy.get("enabled"):
            text = "Sudaeon is off. No policy is enforced and everything below is disabled."
        self.status_label.set_text(text)

    # ------------------------------------------------------------------
    # schedule windows
    # ------------------------------------------------------------------

    def _render_windows(self) -> None:
        if self.windows_group is None:
            return
        for index, window in enumerate(list(self.schedule_windows)):
            title = f"{config.schedule._days_brief(window.get('days'))} " \
                    f"{window.get('start')} – {window.get('end')}"
            edit = button("Edit", flat=True,
                          on_click=lambda _b, i=index: self.edit_window(i))
            remove = button("Remove", flat=True,
                            on_click=lambda _b, i=index: self.remove_window(i))
            suffix = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            suffix.append(edit)
            suffix.append(remove)
            row = action_row(title, suffix=suffix, activatable=False)
            self.window_rows.append(row)
            group_add(self.windows_group, row)
        if not self.schedule_windows:
            row = action_row("No windows yet", subtitle="Policy is enforced at all times",
                             activatable=False)
            self.window_rows.append(row)
            group_add(self.windows_group, row)

    def remove_window(self, index: int) -> None:
        if 0 <= index < len(self.schedule_windows):
            del self.schedule_windows[index]
            self.policy.setdefault("schedule", {})["windows"] = self.schedule_windows
            config.stamp_policy(self.policy)
            self.mark_dirty()
            self._rebuild_windows()

    def _rebuild_windows(self) -> None:
        for row in self.window_rows:
            _drop(self.windows_group, row)
        self.window_rows = []
        self._render_windows()

    def edit_window(self, index: int | None) -> None:
        from .schedule_dialog import WindowDialog
        existing = dict(self.schedule_windows[index]) if index is not None else None
        dialog = WindowDialog(self.window, existing,
                              on_save=lambda window: self.save_window(index, window))
        dialog.present()

    def save_window(self, index: int | None, window: dict[str, Any]) -> None:
        if index is None:
            self.schedule_windows.append(window)
        else:
            self.schedule_windows[index] = window
        self.policy.setdefault("schedule", {})["windows"] = self.schedule_windows
        if self.policy["schedule"].get("mode", "always") == "always":
            self.policy["schedule"]["mode"] = "enforce_during"
        config.stamp_policy(self.policy)
        self.mark_dirty()
        self._rebuild_windows()

    # ------------------------------------------------------------------
    # applications
    # ------------------------------------------------------------------

    def _render_apps(self) -> None:
        if self.apps_group is None:
            return
        blocked = self.policy.get("applications", {}).get("blocked") or []
        for entry in blocked:
            remove = button("Remove", flat=True,
                            on_click=lambda _b, app_id=entry["id"]: self.remove_app(app_id))
            row = action_row(entry.get("name") or entry["id"], subtitle=entry.get("id", ""),
                             suffix=remove, activatable=False)
            self.app_rows.append(row)
            group_add(self.apps_group, row)
        if not blocked:
            row = action_row("Nothing is blocked", subtitle="Add an application below",
                             activatable=False)
            self.app_rows.append(row)
            group_add(self.apps_group, row)

    def _rebuild_apps(self) -> None:
        for row in self.app_rows:
            _drop(self.apps_group, row)
        self.app_rows = []
        self._render_apps()

    def add_application(self) -> None:
        from .app_picker import AppPicker
        picker = AppPicker(self.window, on_pick=self.pick_application)
        picker.present()

    def pick_application(self, entry: dict[str, Any]) -> None:
        blocked = self.policy.setdefault("applications", {}).setdefault("blocked", [])
        blocked[:] = [item for item in blocked if item.get("id") != entry["id"]]
        blocked.append(entry)
        self.set_applications_enabled(True)
        if self.rows.get("applications_enabled") is not None:
            set_switch_active(self.rows["applications_enabled"], True)
        config.stamp_policy(self.policy)
        self.mark_dirty()
        self._rebuild_apps()

    def remove_app(self, app_id: str) -> None:
        blocked = self.policy.setdefault("applications", {}).setdefault("blocked", [])
        blocked[:] = [item for item in blocked if item.get("id") != app_id]
        config.stamp_policy(self.policy)
        self.mark_dirty()
        self._rebuild_apps()

    # ------------------------------------------------------------------
    # users / audit reloads
    # ------------------------------------------------------------------

    def reload_users(self) -> None:
        new_policy = self.policy
        entries = users.list_users(new_policy)
        for name, combo in self.role_combos.items():
            record = next((item for item in entries if item["name"] == name), None)
            if record is None:
                continue
            role = record.get("role") or config.role_for(new_policy, name)
            if role in ROLE_ORDER:
                combo.set_selected(ROLE_ORDER.index(role))
        if self.toast_overlay:
            toast(self.toast_overlay, "Account list refreshed")

    def reload_audit(self) -> None:
        if self.audit_list is None:
            return
        while self.audit_list.get_first_child() is not None:
            self.audit_list.remove(self.audit_list.get_first_child())
        result = privilege.call_helper("audit-tail", args=(), prefer_pkexec=False,
                                       stdin='{"limit": 200}')
        entries = (result.data or {}).get("entries") if result.ok else None
        if not entries:
            local = audit.read(limit=200)
            entries = local if local else []
        for entry in reversed(entries[-200:]):
            row = Gtk.ListBoxRow()
            text = audit.format_entry(entry)
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            box.set_margin_top(4)
            box.set_margin_bottom(4)
            box.set_margin_start(8)
            box.set_margin_end(8)
            result_name = str(entry.get("result", ""))
            icon = "dialog-warning-symbolic" if result_name in {"master-fail", "deny", "error"} \
                else ("emblem-ok-symbolic" if result_name in {"master-ok", "allow"} else "info")
            glyph = Gtk.Image.new_from_icon_name(icon)
            box.append(glyph)
            box.append(label(text, dim=result_name not in {"master-fail", "deny"}))
            row.set_child(box)
            self.audit_list.append(row)

    def clear_audit(self) -> None:
        if not self.ensure_unlocked("Clear the audit log"):
            return
        result = privilege.call_helper_with_master("audit-clear", self.password)
        if not result.ok:
            self._error(result.error or "the audit log could not be cleared")
            return
        self.reload_audit()
        if self.toast_overlay:
            toast(self.toast_overlay, "Audit log cleared")

    # ------------------------------------------------------------------
    # actions
    # ------------------------------------------------------------------

    def ensure_unlocked(self, verb: str) -> bool:
        minutes = int(self.policy.get("advanced", {}).get("unlock_minutes", 5) or 5)
        if self.password and time.monotonic() < self.unlocked_until:
            return True
        password = _ask_password_capture(self.window, verb=verb)
        if not password:
            return False
        self.password = password
        self.unlocked_until = time.monotonic() + max(0, minutes) * 60
        return True

    def apply_changes(self) -> None:
        if not self.is_dirty():
            return
        if not self.ensure_unlocked("Save the policy"):
            return
        config.stamp_policy(self.policy)
        result = privilege.call_helper_with_master("set-policy", self.password,
                                                   {"policy": self.policy})
        if not result.ok:
            self._error(result.error or "the policy could not be saved")
            return
        self.policy = config.normalize_policy((result.data or {}).get("policy") or self.policy)
        self.original = copy.deepcopy(self.policy)
        self.schedule_windows = [dict(item)
                                 for item in (self.policy.get("schedule", {}).get("windows") or [])]
        self.mark_dirty()
        self._refresh_status()
        self._report_warnings(result.data or {})
        if self.toast_overlay:
            toast(self.toast_overlay, "Policy saved")

    def revert_changes(self) -> None:
        self.policy = copy.deepcopy(self.original)
        self.schedule_windows = [dict(item)
                                 for item in (self.policy.get("schedule", {}).get("windows") or [])]
        self._reload_widgets()
        self.mark_dirty()

    def _reload_widgets(self) -> None:
        for key, row in self.rows.items():
            if key in config.ACTIONS:
                set_switch_active(row, config.action_allowed(self.policy, key))
        for key in ("sudo", "user_management", "polkit_admin", "package_management",
                    "removable_media", "root_login"):
            if key in self.rows:
                set_switch_active(self.rows[key], not config.action_allowed(self.policy, key))
        if "enabled" in self.rows:
            set_switch_active(self.rows["enabled"], bool(self.policy.get("enabled")))
        self._sync_sensitivity()
        self._refresh_status()
        self._rebuild_windows()
        self._rebuild_apps()

    def _report_warnings(self, data: dict[str, Any]) -> None:
        report = data.get("report") or {}
        warnings = report.get("warnings") or []
        if warnings:
            self._warning("Saved with warnings", "\n".join(warnings[:6]))

    def _warning(self, heading: str, body: str) -> None:
        message_dialog(self.window, heading, body, responses=[("ok", "OK")],
                       default="ok", on_response=lambda _i: None)

    def _error(self, body: str) -> None:
        message_dialog(self.window, "Sudaeon", body, responses=[("ok", "OK")],
                       default="ok", on_response=lambda _i: None)

    # ---- menu actions ----

    def on_doctor(self) -> None:
        from .. import diagnostics
        report = diagnostics.run_checks()
        text = diagnostics.format_report(report)
        message_dialog(self.window, "Sudaeon Diagnostics", text, responses=[("ok", "Close")],
                       default="ok", on_response=lambda _i: None)

    def on_docs(self) -> None:
        for candidate in ("/usr/share/doc/sudaeon/README.md", "/usr/share/doc/sudaeon/README"):
            if os.path.exists(candidate):
                self._show_text_file(candidate)
                return
        root = paths.REPO_DIR / "docs"
        if root.exists():
            self._show_text_file(str(root / "USAGE.md"))
            return
        self._error("The documentation is not installed.")

    def _show_text_file(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read()[:20000]
        except OSError as exc:
            self._error(str(exc))
            return
        window = make_window(self.app, title="Sudaeon Documentation", width=760, height=640)
        view = Gtk.TextView()
        view.set_editable(False)
        view.set_monospace(True)
        view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        view.get_buffer().set_text(text)
        window.set_child(scrolled(view))
        window.present()

    def on_terminal(self) -> None:
        command = ["gnome-terminal", "--", str(paths.CLI_BIN), "status"]
        for candidate in (command, ["kgx", "--", str(paths.CLI_BIN), "status"],
                          ["x-terminal-emulator", "-e", f"{paths.CLI_BIN} status"],
                          ["xterm", "-e", f"{paths.CLI_BIN} status"]):
            from ..util import which
            if which(candidate[0]):
                try:
                    import subprocess
                    subprocess.Popen(candidate)
                    return
                except OSError as exc:
                    log(str(exc))
        self._error("No terminal emulator was found.")

    def on_about(self) -> None:
        from ..version import APP_VERSION, APP_NAME, APP_SUMMARY
        if HAS_ADW:
            about = Adw.AboutWindow(transient_for=self.window, application_name=APP_NAME,
                                    application_icon="com.sudaeon.Sudaeon",
                                    version=APP_VERSION,
                                    comments=APP_SUMMARY,
                                    developer_name="Sudaeon",
                                    license_type=Gtk.License.GPL_3_0,
                                    website="https://github.com/aswartzlander2-sys/sudaeon")
            about.set_modal(True)
            about.present()
            return
        message_dialog(self.window, f"About {APP_NAME}",
                       f"{APP_NAME} {APP_VERSION}\n\n{APP_SUMMARY}",
                       responses=[("ok", "Close")], default="ok",
                       on_response=lambda _i: None)

    def on_lock(self) -> None:
        self.password = ""
        self.unlocked_until = 0.0
        if self.toast_overlay:
            toast(self.toast_overlay, "Dashboard locked; the master password is required again")

    def on_uninstall(self) -> None:
        message_dialog(
            self.window, "Remove Sudaeon?",
            "Sudaeon will be removed from this computer: the PAM module, the polkit rules "
            "and the sudoers entry are removed and enforcement stops immediately. The "
            "master password and audit log are kept unless you ask for a full purge.",
            responses=[("cancel", "Cancel"), ("remove", "Remove"), ("purge", "Remove and purge")],
            destructive="remove", default="cancel",
            on_response=lambda identifier: self._do_uninstall(identifier))

    def _do_uninstall(self, identifier: str) -> None:
        if identifier == "cancel":
            return
        password = _ask_password_capture(self.window, verb="Remove Sudaeon")
        if not password:
            return
        payload = {"purge": identifier == "purge"}
        result = privilege.call_helper_with_master("uninstall", password, payload, prefer_pkexec=True)
        if not result.ok:
            self._error(result.error or "Sudaeon could not be removed")
            return
        message_dialog(self.window, "Sudaeon removed",
                       "Sudaeon has been removed from this computer. This window will close.",
                       responses=[("ok", "Close")], default="ok",
                       on_response=lambda _i: self.app.quit())

    def repair(self) -> None:
        if not self.ensure_unlocked("Repair the enforcement files"):
            return
        result = privilege.call_helper_with_master("repair", self.password)
        if not result.ok:
            self._error(result.error or "repair failed")
            return
        if self.toast_overlay:
            toast(self.toast_overlay, "Enforcement files rewritten")

    def restart_sentinel(self) -> None:
        result = privilege.call_helper("service", stdin='{"action": "restart"}', prefer_pkexec=True)
        if not result.ok:
            self._error(result.error or "the sentinel could not be restarted")
            return
        if self.toast_overlay:
            toast(self.toast_overlay, "Sentinel restarted")

    def restore_defaults(self) -> None:
        if not self.ensure_unlocked("Restore the default policy"):
            return
        policy = config.default_policy()
        policy["install"] = self.policy.get("install", {})
        policy["users"] = self.policy.get("users", {})
        result = privilege.call_helper_with_master("set-policy", self.password, {"policy": policy})
        if not result.ok:
            self._error(result.error or "the policy could not be restored")
            return
        self.policy = config.normalize_policy((result.data or {}).get("policy") or policy)
        self.original = copy.deepcopy(self.policy)
        self._reload_widgets()
        self.mark_dirty()
        if self.toast_overlay:
            toast(self.toast_overlay, "Default policy restored")

    # ---- master password management ----

    def change_password(self) -> None:
        old = _ask_password_capture(self.window, verb="Change the master password")
        if not old:
            return
        new = _ask_new_password(self.window, "New master password")
        if not new:
            return
        confirm = _ask_new_password(self.window, "Repeat the new master password")
        if confirm != new:
            self._error("The two passwords are different.")
            return
        result = privilege.call_helper("change-master", stdin=_json_body({"old": old, "new": new}),
                                       prefer_pkexec=True)
        if not result.ok:
            self._error(result.error or "the master password could not be changed")
            return
        self.password = new
        self.unlocked_until = time.monotonic() + 300
        if self.toast_overlay:
            toast(self.toast_overlay, "Master password changed")

    def show_recovery_key(self) -> None:
        password = _ask_password_capture(self.window, verb="Show the recovery key")
        if not password:
            return
        result = privilege.call_helper_with_master("show-recovery", password)
        if not result.ok:
            self._error(result.error or "the recovery key could not be read")
            return
        key = (result.data or {}).get("recovery_key", "")
        from .. import crypto
        pretty = crypto.recovery_key_display(key)
        message_dialog(self.window, "Sudaeon Recovery Key",
                       f"Keep this key somewhere safe. It is the only way to reset the master "
                       f"password if it is forgotten.\n\n{pretty}",
                       responses=[("ok", "Close")], default="ok", on_response=lambda _i: None)

    def regenerate_recovery_key(self) -> None:
        password = _ask_password_capture(self.window, verb="Create a new recovery key")
        if not password:
            return
        result = privilege.call_helper_with_master("regenerate-recovery", password)
        if not result.ok:
            self._error(result.error or "the recovery key could not be changed")
            return
        from .. import crypto
        key = crypto.recovery_key_display((result.data or {}).get("recovery_key", ""))
        message_dialog(self.window, "New Recovery Key",
                       f"The previous recovery key no longer works.\n\n{key}",
                       responses=[("ok", "Close")], default="ok", on_response=lambda _i: None)

    def reset_password(self) -> None:
        from .reset_dialog import ResetPasswordDialog
        dialog = ResetPasswordDialog(self.window, on_done=self._after_reset)
        dialog.present()

    def _after_reset(self, new_password: str, recovery_key: str) -> None:
        self.password = new_password
        self.unlocked_until = time.monotonic() + 300
        from .. import crypto
        pretty = crypto.recovery_key_display(recovery_key) if recovery_key else ""
        body = "The master password has been reset."
        if pretty:
            body += f"\n\nRecovery key:\n{pretty}"
        message_dialog(self.window, "Sudaeon", body, responses=[("ok", "Close")],
                       default="ok", on_response=lambda _i: None)


# ---------------------------------------------------------------------------
# password capture helpers
# ---------------------------------------------------------------------------

def _drop(container: Any, child: Any) -> None:
    try:
        container.remove(child)
    except Exception:
        try:
            container.remove(child)  # Adw fallback name on some versions
        except Exception:
            pass


def _json_body(payload: dict[str, Any]) -> str:
    import json
    return "\n" + json.dumps(payload)


def _ask_password_capture(parent, *, verb: str = "") -> str | None:
    """Prompt for the master password and return the text (or None)."""
    from . import password_dialog
    return password_dialog.capture(parent, verb=verb)


def _ask_new_password(parent, title: str) -> str | None:
    from . import password_dialog
    return password_dialog.capture_new(parent, title=title)


def _power_hint(key: str) -> str:
    return {
        "reboot": "Restart the computer from the menu, the terminal or a script",
        "poweroff": "Shut the computer down",
        "halt": "Stop the system without powering it off",
        "suspend": "Sleep",
        "hibernate": "Suspend to disk",
        "hybrid_sleep": "Suspend to memory and disk",
        "suspend_then_hibernate": "Sleep, then hibernate after a while",
        "kexec": "Boot another kernel without a full restart",
        "soft_reboot": "Restart systemd only",
    }.get(key, "")
