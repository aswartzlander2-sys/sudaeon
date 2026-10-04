"""Tests for the Debian packaging and for the process helper contract.

Two things are checked here.

*The packaging*: ``debian/`` has to stay buildable with nothing but
``build-essential``, ``dpkg-dev``, ``libpam0g-dev`` and ``python3`` - no
debhelper, no fakeroot - because that is what ``tools/build-deb.sh`` promises
to somebody who downloaded the source as a ZIP.  The interesting invariants are
that every file ``debian/rules`` declares as a conffile is really installed,
that the version in ``debian/changelog`` matches ``sudaeon/version.py``, that
the maintainer scripts are valid POSIX shell and executable, and that nothing
in ``debian/rules`` calls ``dh_*``.

*The process helper*: :func:`sudaeon.util.run` collects output as text, not as
bytes.  That was once wrong in fifteen places at once (``proc.stderr or b""``
followed by ``.decode()``), which only shows up when a command actually prints
something - i.e. on a real machine, never in a quiet test.  Two tests keep it
fixed: one asserts the type of the collected output, one scans the sources for
the old pattern.

Run the tests with::

    python3 -m unittest tests.test_package -v
"""

from __future__ import annotations

import re
import shutil
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sudaeon import apply as apply_mod  # noqa: E402
from sudaeon import util, version  # noqa: E402

DEBIAN = ROOT / "debian"
SCRIPTS = ("preinst", "postinst", "prerm", "postrm", "config")


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class ProcessOutputTests(unittest.TestCase):
    """sudaeon.util.run returns text; nothing may decode its output again."""

    def test_run_returns_text(self) -> None:
        proc = util.run(["/bin/echo", "hello"])
        self.assertEqual(proc.returncode, 0)
        self.assertIsInstance(proc.stdout, str)
        self.assertEqual(proc.stdout.strip(), "hello")
        self.assertIsInstance(proc.stderr, str)

    def test_run_reports_missing_programs(self) -> None:
        proc = util.run(["/nonexistent/sudaeon-test-program"])
        self.assertEqual(proc.returncode, 127)
        self.assertIsInstance(proc.stderr, str)
        self.assertIn("not found", proc.stderr)

    def test_systemctl_accepts_talking_output(self) -> None:
        """The regression that broke 'sudaeon configure' on a real machine."""
        real_run, real_which = apply_mod.run, apply_mod.which
        printed = "Created symlink /etc/systemd/system/multi-user.target.wants/...\n"

        def fake_run(argv, **kwargs):  # noqa: ANN001
            return subprocess.CompletedProcess(argv, 0, printed, "")

        apply_mod.run, apply_mod.which = fake_run, lambda name: "/usr/bin/" + name
        try:
            code, message = apply_mod.systemctl("enable", "sudaeon-sentinel.service")
        finally:
            apply_mod.run, apply_mod.which = real_run, real_which
        self.assertEqual(code, 0)
        self.assertIn("Created symlink", message)

    def test_no_bytes_decoding_of_run_output(self) -> None:
        """Guard against somebody re-introducing 'proc.stdout or b""'."""
        pattern = re.compile(r"proc\.(stdout|stderr)[^\n]*\.decode\(")
        offenders = []
        for path in sorted((ROOT / "src" / "sudaeon").rglob("*.py")):
            for number, line in enumerate(read(path).splitlines(), 1):
                if pattern.search(line):
                    offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
        self.assertEqual(offenders, [], "these call sites decode run() output again:\n"
                                        + "\n".join(offenders))


class DebianDirectoryTests(unittest.TestCase):
    def test_required_files(self) -> None:
        for name in ("changelog", "control", "copyright", "rules", "postinst", "prerm",
                     "postrm"):
            self.assertTrue((DEBIAN / name).is_file(), f"debian/{name} is missing")
        self.assertTrue((DEBIAN / "source" / "format").is_file())

    def test_version_matches_the_program(self) -> None:
        first = read(DEBIAN / "changelog").splitlines()[0]
        match = re.match(r"^sudaeon \(([^)]+)\) (\S+); urgency=(\w+)$", first)
        self.assertIsNotNone(match, f"malformed changelog header: {first!r}")
        upstream = match.group(1).split("-")[0]
        self.assertEqual(upstream, version.APP_VERSION)
        self.assertEqual(match.group(2), "noble")
        stamp = [line for line in read(DEBIAN / "changelog").splitlines()
                 if line.startswith(" -- ")]
        self.assertTrue(stamp, "the changelog has no maintainer/timestamp line")

    @unittest.skipUnless(shutil.which("dpkg-parsechangelog"), "dpkg-dev is not installed")
    def test_dpkg_can_parse_the_changelog(self) -> None:
        proc = util.run(["dpkg-parsechangelog", "--file", str(DEBIAN / "changelog")])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(f"Version: {version.APP_VERSION}", proc.stdout)

    def test_control_file(self) -> None:
        control = read(DEBIAN / "control")
        self.assertIn("Source: sudaeon", control)
        self.assertIn("Package: sudaeon", control)
        self.assertIn("Architecture: any", control)
        self.assertIn("Rules-Requires-Root: no", control)
        self.assertIn("Build-Depends:", control)
        self.assertNotIn("debhelper", control, "the build must work without debhelper")
        # Debian folds long fields over several lines; join them back together
        fields: dict[str, str] = {}
        for line in control.splitlines():
            if line[:1] in (" ", "\t") and fields:
                key = next(reversed(fields))
                fields[key] += " " + line.strip()
            elif ":" in line:
                key, _, value = line.partition(":")
                fields[key.strip()] = value.strip()
        self.assertIn("libpam0g", fields.get("Depends", ""))
        self.assertIn("python3", fields.get("Depends", ""))
        self.assertIn("libpam-runtime", fields.get("Depends", ""))
        self.assertIn("python3-gi", fields.get("Recommends", ""))

    def test_rules_is_a_plain_makefile(self) -> None:
        rules = read(DEBIAN / "rules")
        self.assertTrue((DEBIAN / "rules").stat().st_mode & 0o111, "debian/rules is not executable")
        self.assertNotIn("dh_", rules, "debian/rules must not call debhelper")
        for target in ("build", "binary", "binary-arch", "clean"):
            self.assertRegex(rules, rf"(?m)^(?!\\t).*\b{re.escape(target)}[ :]",
                             f"debian/rules has no '{target}' target")
        self.assertIn("dpkg-deb", rules)
        self.assertIn("--root-owner-group", rules, "the archive must be root owned")

    def conffiles(self) -> list[str]:
        rules = read(DEBIAN / "rules")
        body = rules.split("CONFFILES :=", 1)[1].split(".PHONY", 1)[0]
        return [item for item in body.replace("\\", " ").split() if item.startswith("/")]

    def test_declared_conffiles_are_produced(self) -> None:
        """Every conffile dpkg records has to be written by the installer."""
        conffiles = self.conffiles()
        self.assertTrue(conffiles, "debian/rules declares no conffiles")
        with tempfile.TemporaryDirectory(prefix="sudaeon-conffiles-") as tmp:
            proc = util.run([sys.executable, str(ROOT / "tools" / "gen-assets.py"),
                             "--root", tmp, "--no-icons", "--quiet"], timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            for path in conffiles:
                rendered = Path(tmp) / path.lstrip("/")
                self.assertTrue(rendered.is_file(), f"{path} is a conffile but was not rendered")

    def test_maintainer_scripts_are_shell_and_executable(self) -> None:
        for name in SCRIPTS:
            path = DEBIAN / name
            if not path.exists():
                continue
            self.assertTrue(path.stat().st_mode & 0o111, f"debian/{name} is not executable")
            proc = subprocess.run(["/bin/sh", "-n", str(path)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, f"debian/{name}: {proc.stderr}")
            self.assertTrue(read(path).startswith("#!"), f"debian/{name} has no shebang")

    def test_postinst_uses_the_helper_verb(self) -> None:
        postinst = read(DEBIAN / "postinst")
        self.assertIn("configure-package", postinst)
        self.assertIn("SUDO_USER", postinst)
        self.assertNotIn("dh_", postinst)
        prerm = read(DEBIAN / "prerm")
        self.assertIn("unconfigure-package", prerm)

    def test_helper_verbs_exist(self) -> None:
        from sudaeon import helper

        self.assertIn("configure-package", helper.VERBS)
        self.assertIn("unconfigure-package", helper.VERBS)
        self.assertIn("configure-package", helper.PACKAGE_VERBS)
        self.assertIn("unconfigure-package", helper.PACKAGE_VERBS)
        # the package verbs are the only ones reachable without being an
        # administrator, because dpkg runs them before one exists
        self.assertNotIn("install", helper.PACKAGE_VERBS)
        self.assertNotIn("uninstall", helper.PACKAGE_VERBS)


class BuildScriptTests(unittest.TestCase):
    def test_build_deb_exists_and_is_portable(self) -> None:
        script = ROOT / "tools" / "build-deb.sh"
        self.assertTrue(script.is_file(), "tools/build-deb.sh is missing")
        self.assertTrue(script.stat().st_mode & 0o111, "tools/build-deb.sh is not executable")
        text = read(script)
        self.assertTrue(text.startswith("#!/bin/sh"), "use /bin/sh, not bash")
        self.assertIn("dpkg-buildpackage", text)
        self.assertIn("-us -uc", text, "the build must not try to sign anything")
        proc = subprocess.run(["/bin/sh", "-n", str(script)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        code = "\n".join(line for line in text.splitlines()
                          if not line.lstrip().startswith("#"))
        for forbidden in ("dh_", "fakeroot", "debhelper"):
            self.assertNotIn(forbidden, code, f"{forbidden} must not be needed")

    def test_install_ships_no_byte_code(self) -> None:
        """The interpreter on the target machine compiles the .pyc files."""
        makefile = read(ROOT / "Makefile")
        self.assertNotIn("compileall", makefile)
        self.assertIn("__pycache__", makefile)

    def test_built_package_tree_has_no_byte_code(self) -> None:
        tree = DEBIAN / "sudaeon"
        if not tree.exists():
            self.skipTest("no package tree has been built in this checkout")
        stray = [str(path.relative_to(ROOT)) for path in tree.rglob("*.pyc")]
        self.assertEqual(stray, [], "byte-code ended up in the package")

    def test_makefile_has_a_deb_target(self) -> None:
        makefile = read(ROOT / "Makefile")
        self.assertIn("\ndeb:", makefile)
        self.assertIn("tools/build-deb.sh", makefile)
        self.assertRegex(makefile, r"(?m)^deb:\s*\S",
                         "deb should have a prerequisite, so 'make deb' builds first")

    def test_source_tree_is_packagable(self) -> None:
        """Everything a ZIP download needs is there, and build output is ignored."""
        for name in ("Makefile", "debian", "src", "tools", "tests"):
            self.assertTrue((ROOT / name).exists(), f"{name} is missing from the tree")
        for name in ("debian/sudaeon/", "dist/", "build/", "__pycache__/"):
            self.assertIn(name, read(ROOT / ".gitignore"),
                          f"{name} should not end up in the repository")

    @unittest.skipUnless(shutil.which("git") and (ROOT / ".git").exists(), "no git checkout")
    def test_build_output_is_ignored_by_git(self) -> None:
        generated = [ROOT / "build" / "sudaeon-chkpwd",
                     ROOT / "src" / "sudaeon" / "__pycache__" / "x.pyc",
                     ROOT / "debian" / "sudaeon" / "usr" / "bin" / "sudaeon",
                     ROOT / "dist" / "sudaeon_1.0.0_amd64.deb"]
        existing = [path for path in generated if path.exists()]
        if not existing:
            self.skipTest("nothing has been built yet")
        for path in existing:
            code = util.run(["git", "check-ignore", "-q", str(path)], cwd=str(ROOT)).returncode
            self.assertEqual(code, 0, f"{path.relative_to(ROOT)} is not ignored by git")


if __name__ == "__main__":
    unittest.main(verbosity=2)
