#!/usr/bin/env python3
"""Render Sudaeon's static system integration files into a target directory.

The files that the program needs at runtime but that never change (the desktop
entry, the autostart entry, the systemd unit, the tmpfiles rule, the logrotate
configuration, the polkit rule and action, the sudoers drop-in and the icons)
are generated here from the same templates the program uses, so there is one
source of truth and no per-distribution copies to keep in sync.

``make install`` calls this with the package root, and so does
``debian/rules``; you can also run it by hand to see what an installation
would look like::

    tools/gen-assets.py --root /tmp/sudaeon-assets
    find /tmp/sudaeon-assets -type f

Everything is written below the given root, which is normally ``DESTDIR``, so
the paths produced are absolute system paths ("/usr/share/...").  The script
needs no privileges.
"""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# The output must describe the *system* layout, never a sandbox.
os.environ.pop("SUDAEON_ROOT", None)
os.environ.pop("SUDAEON_NO_SANDBOX", None)

from sudaeon import apply as apply_mod  # noqa: E402
from sudaeon import brand, config, installer, paths  # noqa: E402
from sudaeon.version import ADMIN_GROUP, APP_ID, APP_VERSION  # noqa: E402


def write(root: Path, relative: str, text: str, mode: int = 0o644) -> Path:
    target = root / relative.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    os.chmod(target, mode)
    return target


def polkit_rule() -> str:
    """The polkit rule, byte for byte what ``apply.write_polkit_rules`` writes."""
    from sudaeon import engine

    prefixes = "\n".join(f'        "{prefix}",' for prefix, _key in engine.POLKIT_PREFIXES)
    return apply_mod.POLKIT_RULES_TEMPLATE.format(prefixes=prefixes.rstrip(","),
                                                  guard=paths.POLKIT_GUARD)


TMPFILES = """# Sudaeon: the runtime directory of the sentinel service.
d /run/sudaeon 0755 root root -
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default="", help="target root (DESTDIR); "
                                                   "default: a directory below /tmp")
    parser.add_argument("--no-icons", action="store_true",
                        help="skip the icon set even when assets/ has a logo")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.root or "/tmp/sudaeon-assets").resolve()
    root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    def note(message: str) -> None:
        if not args.quiet:
            print(message)

    # the launcher: the package owns /usr/bin/sudaeon, and it is byte for byte
    # what the self installer would write
    written.append(write(root, str(paths.CLI_BIN).lstrip("/"), installer.CLI_SHIM,
                         0o755))

    # desktop integration -------------------------------------------------
    written.append(write(root, "usr/share/applications/com.sudaeon.Sudaeon.desktop",
                         brand.desktop_entry(str(paths.CLI_BIN))))
    written.append(write(root, str(paths.AGENT_AUTOSTART).lstrip("/"),
                         brand.agent_autostart_entry()))

    # systemd / tmpfiles / logrotate --------------------------------------
    written.append(write(root, str(paths.SYSTEMD_SENTINEL_UNIT).lstrip("/"),
                         brand.systemd_unit()))
    written.append(write(root, str(paths.TMPFILES_FILE).lstrip("/"), TMPFILES))
    written.append(write(root, str(paths.LOGROTATE_FILE).lstrip("/"),
                         brand.logrotate_config()))

    # polkit: the action that allows pkexec to run the helper, and the rule
    # that routes every managed action through the guard.
    written.append(write(root, str(paths.POLKIT_ACTION_FILE).lstrip("/"),
                         apply_mod.POLKIT_ACTION_TEMPLATE.format(cli=paths.CLI_BIN)))
    written.append(write(root, str(paths.POLKIT_RULES_FILE).lstrip("/"), polkit_rule()))

    # sudoers: the helper is reachable without a password, but the helper
    # demands the master password for every change it makes.
    written.append(write(root, str(paths.SUDOERS_FILE).lstrip("/"),
                         apply_mod.SUDOERS_TEMPLATE.format(group=ADMIN_GROUP,
                                                           helper=paths.HELPER_BIN),
                         0o440))

    # documentation --------------------------------------------------------
    written.append(write(root, str(paths.ETC_DIR / "README").lstrip("/"),
                         installer.README_ETC))
    for name in ("README.md", "LICENSE"):
        source = ROOT / name
        if source.exists():
            target = root / "usr/share/doc/sudaeon" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            written.append(target)

    # icons ----------------------------------------------------------------
    if not args.no_icons:
        icon_root = root / str(paths.ICON_ROOT).lstrip("/")
        report = brand.build_icons(icon_root, verbose=False, cache=False)
        source = report.get("source")
        if source:
            note(f"icons: rendered from {source}")
            written.extend(Path(item) for item in report["rendered"])
            if report.get("symbolic"):
                written.append(Path(str(report["symbolic"])))
        else:
            note("icons: no logo in assets/ - the desktop entry falls back to a "
                 "stock icon name (drop your logo in assets/sudaeon.svg and rebuild)")

    # the state directories belong to the package so that dpkg removes them
    for relative, mode in ((str(paths.STATE_DIR).lstrip("/"), 0o755),
                           (str(paths.STATE_DIR / "backup").lstrip("/"), 0o700),
                           (str(paths.APPGATE_DIR).lstrip("/"), 0o755),
                           (str(paths.LOG_DIR).lstrip("/"), 0o750)):
        target = root / relative
        target.mkdir(parents=True, exist_ok=True)
        os.chmod(target, mode)

    note(f"{len(written)} files under {root}")
    return 0


if __name__ == "__main__":  # pragma: no cover - command line helper
    raise SystemExit(main())
