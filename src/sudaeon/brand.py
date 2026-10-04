"""Application icon handling.

The shipped mark lives in ``assets/sudaeon.svg``.  Replace that file with your
own logo and run ``make icons`` to regenerate every size; nothing else needs to
change.  Rendering uses whichever converter is available (cairosvg, rsvg-convert,
inkscape or ImageMagick), and if none of them is installed the SVG itself is used
as the icon source.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from . import paths
from .version import APP_ID
from .util import log, run, which

SIZES = (16, 22, 24, 32, 48, 64, 96, 128, 256, 512)

REPO_ASSETS = paths.REPO_DIR / "assets"
SOURCE_SVG = REPO_ASSETS / "sudaeon.svg"
SYMBOLIC_SVG = REPO_ASSETS / "sudaeon-symbolic.svg"


def source_svg() -> Path | None:
    for candidate in (SOURCE_SVG, REPO_ASSETS / "sudaeon.png",
                      REPO_ASSETS / "sudaeon.jpg", REPO_ASSETS / "logo.svg",
                      REPO_ASSETS / "logo.png"):
        if candidate.exists():
            return candidate
    return None


def _convert(source: Path, target: Path, size: int) -> bool:
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.suffix.lower() == ".svg":
        if which("rsvg-convert"):
            proc = run(["rsvg-convert", "-w", str(size), "-h", str(size),
                        "-o", str(target), str(source)], timeout=60)
            if proc.returncode == 0 and target.exists():
                return True
        if which("inkscape"):
            proc = run(["inkscape", str(source), "-w", str(size), "-h", str(size),
                        "-o", str(target)], timeout=120)
            if proc.returncode == 0 and target.exists():
                return True
        if which("convert"):
            proc = run(["convert", "-background", "none", "-resize", f"{size}x{size}",
                        str(source), str(target)], timeout=60)
            if proc.returncode == 0 and target.exists():
                return True
        try:  # pragma: no cover - optional dependency
            import cairosvg
            cairosvg.svg2png(url=str(source), write_to=str(target),
                             output_width=size, output_height=size)
            return target.exists()
        except Exception:
            return False
    else:
        if which("convert"):
            proc = run(["convert", str(source), "-resize", f"{size}x{size}", str(target)],
                       timeout=60)
            if proc.returncode == 0 and target.exists():
                return True
        try:
            from PIL import Image  # type: ignore
            image = Image.open(source)
            image.thumbnail((size, size))
            image.save(target)
            return True
        except Exception:
            return False
    return False


def build_icons(target_root: Path | None = None, *, verbose: bool = True,
                cache: bool = True) -> dict[str, object]:
    """Render the hicolor icon set.  Returns a report dictionary."""
    source = source_svg()
    report: dict[str, object] = {"source": str(source) if source else None,
                                 "rendered": [], "failed": [], "symbolic": None}
    if source is None:
        if verbose:
            log("no logo found in assets/ - skipping icon generation")
        return report
    root = target_root or paths.ICON_ROOT
    for size in SIZES:
        target = root / f"{size}x{size}" / "apps" / f"{APP_ID}.png"
        if _convert(source, target, size):
            report["rendered"].append(str(target))
        else:
            report["failed"].append(size)
    # symbolic (monochrome) icon used in menus and the tray
    symbolic_src = SYMBOLIC_SVG if SYMBOLIC_SVG.exists() else source
    for size in (16, 24, 32, 48, 96, 256):
        target = root / f"{size}x{size}" / "apps" / f"{APP_ID}-symbolic.png"
        if _convert(symbolic_src, target, size):
            report["rendered"].append(str(target))
    try:
        scalar = root / "scalable" / "apps" / f"{APP_ID}.svg"
        scalar.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, scalar)
        report["symbolic"] = str(scalar)
    except OSError:
        pass
    if cache and which("gtk-update-icon-cache") and root.exists():
        run(["gtk-update-icon-cache", "-q", "-t", "-f", str(root)], timeout=60)
    if verbose:
        log(f"icon: {len(report['rendered'])} files from {source}")
    return report


def desktop_entry(exec_line: str = "sudaeon", *, name: str = "Sudaeon",
                  comment: str = "Parental controls and master password policy",
                  extra: str = "") -> str:
    return f"""[Desktop Entry]
Type=Application
Name={name}
GenericName=Parental Controls
Comment={comment}
Exec={exec_line}
Icon={APP_ID}
Terminal=false
Categories=System;Settings;Security;
Keywords=parental;control;policy;password;shutdown;sudo;
StartupNotify=true
{extra}"""


def agent_autostart_entry() -> str:
    return f"""[Desktop Entry]
Type=Application
Name=Sudaeon Permission Agent
Comment=Shows Sudaeon master password prompts in this session
Exec={paths.CLI_BIN} agent
Icon={APP_ID}
Terminal=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Phase=Applications
OnlyShowIn=GNOME;KDE;XFCE;MATE;Cinnamon;Budgie;Unity;LXQt;LXDE;
"""


def systemd_unit() -> str:
    return f"""[Unit]
Description=Sudaeon policy sentinel (parental controls enforcement)
Documentation=man:sudaeon(1)
ConditionPathExists={paths.INSTALL_MARKER}
After=dbus.service systemd-logind.service
PartOf=graphical.target

[Service]
Type=simple
ExecStart={paths.SENTINEL_BIN}
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2
User=root
Slice=system.slice
# The sentinel reads the power/sleep button devices directly and asks the
# session for the master password before a blocked action is carried out.
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={paths.STATE_DIR} {paths.RUN_DIR} {paths.LOG_DIR}
PrivateTmp=true
NoNewPrivileges=false
# EVIOCGRAB needs access to /dev/input, logind actions need the system bus
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_KILL CAP_DAC_OVERRIDE CAP_CHOWN CAP_SETUID CAP_SETGID
AmbientCapabilities=CAP_KILL CAP_DAC_OVERRIDE CAP_CHOWN
UMask=0022

[Install]
WantedBy=multi-user.target
"""


def logrotate_config() -> str:
    return f"""{paths.AUDIT_LOG} {paths.AUDIT_LOG_OLD} {{
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
}}
"""
