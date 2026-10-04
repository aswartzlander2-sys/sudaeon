"""Tests for the policy schema, the engine and the rendered enforcement file.

The interesting one is :class:`EnforcementFileTests`: ``enforcement.conf`` is a
contract between Python (which renders it) and C (``cutil.c``, which parses it
for ``pam_sudaeon.so`` and ``sudaeon-chkpwd``).  The test renders a fixed
policy and compares the result with ``tests/fixtures/enforcement.conf``, which
``tests/c/test_util.c`` also parses - so both sides fail when either drifts.

Regenerate the fixture after an intentional format change::

    python3 -m tests.test_config --write-fixture

Run the tests with::

    python3 -m unittest tests.test_config -v
"""

from __future__ import annotations

import copy
import os
import sys
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sudaeon import config, engine, schedule  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "enforcement.conf"


def fixture_policy() -> dict:
    """A policy that exercises every branch of the renderer."""
    policy = config.default_policy()
    policy["enabled"] = True
    policy["enforcement"]["terminal_max_attempts"] = 4
    policy["enforcement"]["prompt_timeout_seconds"] = 90
    policy["enforcement"]["lockout_seconds"] = 60
    policy["enforcement"]["fail_closed"] = True
    policy["enforcement"]["audit_attempts"] = True
    config.set_action(policy, "sudo", False)          # blocked, overridable
    config.set_action(policy, "root_login", False)    # blocked, no override
    config.set_action(policy, "reboot", False)
    config.set_role(policy, "alice", config.ROLE_ADMIN)
    config.set_role(policy, "bob", config.ROLE_EXEMPT)
    config.set_role(policy, "carol", config.ROLE_REGULAR)
    policy["users"]["default_role"] = config.ROLE_REGULAR
    policy["schedule"] = {
        "mode": "enforce_during",
        "windows": [
            {"days": [0, 1, 2, 3, 4], "start": "21:00", "end": "07:00"},
            {"days": [5, 6], "start": "09:00", "end": "17:00"},
        ],
    }
    policy["applications"] = {"enabled": True, "blocked": [
        {"id": "org.gnome.Terminal.desktop", "name": "Terminal"},
    ]}
    return policy


def render_fixture() -> str:
    text = config.render_enforcement_conf(
        fixture_policy(), usernames=["alice", "bob", "carol", "dave"])
    # the timestamp changes every run; the fixture must not
    return "".join(line for line in text.splitlines(keepends=True)
                   if not line.startswith("# generated="))


class PolicySchemaTests(unittest.TestCase):
    def test_default_policy_is_valid(self) -> None:
        policy = config.default_policy()
        self.assertEqual(config.validate_policy(policy), [])
        self.assertTrue(policy["enabled"], "the master switch is on by default")
        self.assertEqual(policy["users"]["default_role"], config.ROLE_REGULAR)

    def test_normalize_fills_missing_keys(self) -> None:
        policy = config.normalize_policy({"enabled": False})
        self.assertFalse(policy["enabled"])
        self.assertIn("sudo", policy["actions"])
        self.assertEqual(policy["enforcement"]["terminal_max_attempts"], 3)
        self.assertEqual(policy["power_button"], "require_master")

    def test_normalize_clamps_ranges(self) -> None:
        policy = config.normalize_policy({
            "enforcement": {"terminal_max_attempts": 99, "prompt_timeout_seconds": 1,
                            "lockout_seconds": -5}})
        self.assertEqual(policy["enforcement"]["terminal_max_attempts"], 10)
        self.assertEqual(policy["enforcement"]["prompt_timeout_seconds"], 15)
        self.assertEqual(policy["enforcement"]["lockout_seconds"], 0)

    def test_normalize_rejects_junk(self) -> None:
        policy = config.normalize_policy({"enabled": "yes please",
                                          "users": {"roles": {"root": "admin"}}})
        self.assertTrue(policy["enabled"])
        self.assertNotIn("root", policy["users"]["roles"])

    def test_roles(self) -> None:
        policy = config.default_policy()
        config.set_role(policy, "alice", config.ROLE_ADMIN)
        config.set_role(policy, "bob", config.ROLE_EXEMPT)
        self.assertEqual(config.role_for(policy, "root"), "root")
        self.assertEqual(config.role_for(policy, "alice"), config.ROLE_ADMIN)
        self.assertEqual(config.role_for(policy, "bob"), config.ROLE_EXEMPT)
        self.assertEqual(config.role_for(policy, "carol"), config.ROLE_REGULAR)
        self.assertTrue(config.can_open_dashboard(policy, "alice"))
        self.assertFalse(config.can_open_dashboard(policy, "carol"))
        self.assertTrue(config.is_subject(policy, "carol"))
        self.assertFalse(config.is_subject(policy, "bob"))

    def test_set_role_rejects_unknown_role(self) -> None:
        policy = config.default_policy()
        with self.assertRaises(ValueError):
            config.set_role(policy, "alice", "superuser")


class EnforcementFileTests(unittest.TestCase):
    def test_matches_the_committed_fixture(self) -> None:
        self.assertTrue(FIXTURE.exists(), f"missing {FIXTURE}")
        self.assertEqual(render_fixture(), FIXTURE.read_text())

    def test_has_the_keys_the_c_parser_reads(self) -> None:
        text = render_fixture()
        for key in ("schema=", "enabled=", "fail_closed=", "audit=", "max_attempts=",
                    "prompt_timeout=", "prompt_text=", "default_role=",
                    "default_require=", "verifier=", "chkpwd="):
            self.assertIn(f"\n{key}", "\n" + text, f"missing {key}")

    def test_window_format_is_readable_by_c(self) -> None:
        # sd_config_load() splits on the last two commas: days, start, end
        self.assertIn("window=Mon,Tue,Wed,Thu,Fri,21:00,07:00", render_fixture())
        self.assertIn("window=Sat,Sun,09:00,17:00", render_fixture())

    def test_broken_application_ids_are_skipped(self) -> None:
        policy = fixture_policy()
        policy["applications"]["blocked"].append({"id": "bad=id", "name": "bad"})
        self.assertNotIn("bad=id", config.render_enforcement_conf(policy))

    def test_unknown_users_are_not_invented(self) -> None:
        text = config.render_enforcement_conf(fixture_policy())
        self.assertNotIn("[user:dave]", text)
        self.assertIn("[user:*]", text)


class SummaryTests(unittest.TestCase):
    def test_summary_mentions_the_state(self) -> None:
        policy = config.default_policy()
        off = config.summary(config.normalize_policy({"enabled": False})).lower()
        self.assertIn("off", off)
        self.assertIn("no policy is enforced", off)
        self.assertIn("on", config.summary(policy).lower())

    def test_schedule_summary(self) -> None:
        policy = fixture_policy()
        text = config.render_enforcement_conf(policy)
        self.assertIn("mode=enforce_during", text)


class EngineTests(unittest.TestCase):
    def test_master_off_allows_everything(self) -> None:
        policy = fixture_policy()
        policy["enabled"] = False
        decision = engine.evaluate(policy, "sudo", "carol")
        self.assertTrue(decision.allowed)
        self.assertIn("turned off", decision.reason)

    def test_exempt_user_bypasses_the_policy(self) -> None:
        policy = fixture_policy()
        decision = engine.evaluate(policy, "sudo", "bob")
        self.assertTrue(decision.allowed)
        self.assertIn("exempt", decision.reason)

    def test_regular_user_is_blocked_and_may_unlock(self) -> None:
        policy = fixture_policy()
        monday_noon = datetime(2026, 10, 5, 12, 0)      # in the Mon-Fri window? no
        decision = engine.evaluate(policy, "sudo", "carol", when=monday_noon)
        # 12:00 is inside no window, so enforcement is off for "enforce_during"
        self.assertTrue(decision.allowed)
        late = datetime(2026, 10, 5, 23, 0)             # inside 21:00-07:00
        decision = engine.evaluate(policy, "sudo", "carol", when=late)
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.require_master)

    def test_root_login_cannot_be_unlocked(self) -> None:
        policy = fixture_policy()
        late = datetime(2026, 10, 5, 23, 0)
        decision = engine.evaluate(policy, "root_login", "carol", when=late)
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.require_master)

    def test_polkit_action_mapping(self) -> None:
        for action_id, key in (("org.freedesktop.login1.reboot-multiple-sessions", "reboot"),
                               ("org.freedesktop.login1.power-off-ignore-inhibit", "poweroff"),
                               ("org.freedesktop.login1.suspend", "suspend"),
                               ("org.freedesktop.accounts.user-administration",
                                "user_management"),
                               ("org.debian.apt.install-or-remove-packages",
                                "package_management"),
                               ("org.freedesktop.udisks2.filesystem-mount", "removable_media")):
            self.assertEqual(engine.action_for_polkit(action_id), key, action_id)
        self.assertEqual(engine.action_for_polkit("org.freedesktop.login1.reboot"), "reboot")
        self.assertIsNone(engine.action_for_polkit(""))
        self.assertIsNone(engine.action_for_polkit("org.example.nothing"))

    def test_pam_service_mapping(self) -> None:
        self.assertEqual(engine.action_for_pam("sudo"), "sudo")
        self.assertEqual(engine.action_for_pam("pkexec"), "sudo")
        self.assertEqual(engine.action_for_pam("passwd"), "user_management")
        self.assertEqual(engine.action_for_pam("gdm-password", "root"), "root_login")
        self.assertIsNone(engine.action_for_pam("gdm-password", "carol"))
        self.assertIsNone(engine.action_for_pam("cron"))


class ScheduleTests(unittest.TestCase):
    def test_window_crossing_midnight(self) -> None:
        window = schedule.make_window([0], "21:00", "07:00")
        self.assertTrue(schedule.in_window(window, datetime(2026, 10, 5, 23, 30)))
        # Tuesday 02:00 belongs to Monday's window
        self.assertTrue(schedule.in_window(window, datetime(2026, 10, 6, 2, 0)))
        self.assertFalse(schedule.in_window(window, datetime(2026, 10, 6, 12, 0)))

    def test_modes(self) -> None:
        during = {"mode": "enforce_during", "windows": [schedule.make_window([0], "21:00", "23:00")]}
        monday_night = datetime(2026, 10, 5, 22, 0)
        monday_noon = datetime(2026, 10, 5, 12, 0)
        self.assertTrue(schedule.active_now(during, monday_night))
        self.assertFalse(schedule.active_now(during, monday_noon))
        outside = {"mode": "enforce_outside",
                   "windows": [schedule.make_window([0], "21:00", "23:00")]}
        self.assertFalse(schedule.active_now(outside, monday_night))
        self.assertTrue(schedule.active_now(outside, monday_noon))
        self.assertTrue(schedule.active_now({"mode": "always", "windows": []}, monday_noon))

    def test_describe(self) -> None:
        text = schedule.describe({"mode": "enforce_during",
                                  "windows": [schedule.make_window([0, 1, 2, 3, 4],
                                                                   "21:00", "07:00")]})
        self.assertIn("21:00", text)
        self.assertIn("07:00", text)


def _write_fixture() -> None:
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(render_fixture())
    print(f"wrote {FIXTURE}")


if __name__ == "__main__":
    if "--write-fixture" in sys.argv:
        _write_fixture()
    else:
        unittest.main(verbosity=2)
