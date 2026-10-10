"""Changes the user asked for: turn protection on/off, schedule the daily check, show a file.

Each one runs the kit's own, reviewed scripts — the dashboard never edits system settings itself.
"""
import os

from .config import IS_MAC, IS_WIN, KIT
from .system import powershell, run


def installer(action, dry_run=False):
    """action: 'install' or 'uninstall'. Returns (exit code, output)."""
    if action not in ("install", "uninstall"):
        raise ValueError("bad action")
    preview = dry_run and action == "install"
    if IS_WIN:
        script = os.path.join(KIT, "windows", action + ".ps1")
        return powershell(script, *(["-DryRun"] if preview else []))
    return run(["bash", os.path.join(KIT, "mac", action + ".sh")] + (["--dry-run"] if preview else []), timeout=600)


def set_routine(on, at="09:00"):
    if IS_WIN:
        return powershell(os.path.join(KIT, "windows", "install-routine.ps1"), *(["-At", at] if on else ["-Remove"]), timeout=120)
    if IS_MAC:
        return run(["bash", os.path.join(KIT, "mac", "install-routine.sh")] + ([at] if on else ["--remove"]), timeout=120)
    return 1, ("The scheduled daily check is available on macOS and Windows. On Linux, add this line with `crontab -e`:\n"
               f"0 9 * * * bash {os.path.join(KIT, 'scan-my-machine.sh')} --quick")


def reveal(path):
    """Show a file or folder in Finder / Explorer / the file manager."""
    if IS_MAC:
        return run(["open", "-R", path], timeout=15)
    if IS_WIN:
        return run(["explorer", "/select," + os.path.normpath(path)], timeout=15)
    return run(["xdg-open", path if os.path.isdir(path) else os.path.dirname(path)], timeout=15)
