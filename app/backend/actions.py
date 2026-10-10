"""Changes the user asked for: turn protection on/off, schedule the daily check, show a file, pick a folder.

Each one runs the kit's own, reviewed scripts — the dashboard never edits system settings itself.
"""
import os
import shutil
import threading

from .config import HOME, IS_MAC, IS_WIN, KIT
from .system import powershell, run

_picker_lock = threading.Lock()
PICKER_PROMPT = "Choose a folder with your projects"


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


def _picker_command():
    """The system's own folder picker, or None when there isn't one (some Linux setups)."""
    if IS_MAC:
        return ["osascript", "-e", "activate", "-e", f'POSIX path of (choose folder with prompt "{PICKER_PROMPT}")']
    if IS_WIN:
        script = ("Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.FolderBrowserDialog; "
                  f"$d.Description = '{PICKER_PROMPT}'; $d.ShowNewFolderButton = $false; "
                  "$top = New-Object System.Windows.Forms.Form -Property @{TopMost = $true}; "
                  "if ($d.ShowDialog($top) -eq 'OK') { $d.SelectedPath }")
        return ["powershell", "-NoProfile", "-STA", "-Command", script]
    if shutil.which("zenity"):
        return ["zenity", "--file-selection", "--directory", f"--title={PICKER_PROMPT}"]
    if shutil.which("kdialog"):
        return ["kdialog", "--getexistingdirectory", HOME, "--title", PICKER_PROMPT]
    return None


def pick_folder(runner=run):
    """Open the native folder picker. Returns {"path": "~/..."} | {"cancelled": True} | {"unavailable": True} | {"busy": True}."""
    cmd = _picker_command()
    if cmd is None:
        return {"unavailable": True}
    if not _picker_lock.acquire(blocking=False):            # one picker at a time
        return {"busy": True}
    try:
        code, out = runner(cmd, timeout=600)
    finally:
        _picker_lock.release()
    path = (out.strip().splitlines() or [""])[-1].strip()
    if code != 0 or not path or not os.path.isabs(path) or not os.path.isdir(path):
        return {"cancelled": True}
    path = os.path.normpath(path)
    if path == HOME or path.startswith(HOME + os.sep):
        path = "~" + path[len(HOME):]                       # shorter to read, and the scripts understand ~
    return {"path": path}


def reveal(path):
    """Show a file or folder in Finder / Explorer / the file manager."""
    if IS_MAC:
        return run(["open", "-R", path], timeout=15)
    if IS_WIN:
        return run(["explorer", "/select," + os.path.normpath(path)], timeout=15)
    return run(["xdg-open", path if os.path.isdir(path) else os.path.dirname(path)], timeout=15)
