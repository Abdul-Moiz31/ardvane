"""Read-only checks of which protections are switched on. Nothing here changes the system."""
import os
import plistlib
import re
import shutil
import threading
import time

from . import launcher
from .config import DEST, HOME, IS_MAC, IS_WIN, KIT, RC_MARKER, ROUTINE_LABEL, ROUTINE_TASK
from .system import run, same_path, sha256


def routine():
    """Daily check: {'available', 'on', 'time': 'HH:MM' | None}."""
    if IS_MAC:
        plist = os.path.join(HOME, "Library", "LaunchAgents", ROUTINE_LABEL + ".plist")
        try:
            with open(plist, "rb") as f:
                interval = plistlib.load(f).get("StartCalendarInterval") or {}
            return {"available": True, "on": True,
                    "time": "%02d:%02d" % (int(interval.get("Hour", 9)), int(interval.get("Minute", 0)))}
        except (OSError, ValueError, plistlib.InvalidFileException):
            return {"available": True, "on": False, "time": None}
    if IS_WIN:
        code, out = run(["schtasks", "/Query", "/TN", ROUTINE_TASK, "/XML"], timeout=20)
        if code != 0:
            return {"available": True, "on": False, "time": None}
        m = re.search(r"<StartBoundary>[^T<]*T(\d{2}):(\d{2})", out)
        return {"available": True, "on": True, "time": f"{m.group(1)}:{m.group(2)}" if m else None}
    return {"available": False, "on": False, "time": None}


def editors():
    """VS Code / Cursor / Windsurf user settings: automatic tasks off and Workspace Trust on?"""
    if IS_WIN:
        base = lambda e: os.path.join(os.environ.get("APPDATA", ""), e, "User")
        names = ("Code", "Cursor", "Windsurf")
    elif IS_MAC:
        base = lambda e: os.path.join(HOME, "Library", "Application Support", e, "User")
        names = ("Code", "Cursor", "Windsurf")
    else:
        base = lambda e: os.path.join(HOME, ".config", e, "User")
        names = ("Code", "Cursor")
    result = []
    for name in names:
        folder = base(name)
        if not os.path.isdir(folder):
            continue
        try:
            with open(os.path.join(folder, "settings.json"), encoding="utf-8") as f:
                text = f.read()
        except OSError:
            text = ""
        result.append({
            "editor": "VS Code" if name == "Code" else name,
            "auto_tasks_off": bool(re.search(r'"task\.allowAutomaticTasks"\s*:\s*"off"', text)),
            "trust_on": not re.search(r'"security\.workspace\.trust\.enabled"\s*:\s*false', text),
        })
    return result


def in_shell_profile(token):
    """Is `token` inside the installer's marked block in one of your shell profiles?"""
    profiles = [os.path.join(HOME, n) for n in (".zshrc", ".bashrc", ".bash_profile")]
    if IS_WIN:
        docs = os.path.join(HOME, "Documents")
        profiles += [os.path.join(docs, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
                     os.path.join(docs, "PowerShell", "Microsoft.PowerShell_profile.ps1")]
    for p in profiles:
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        if RC_MARKER in text and token in text:
            return True
    return False


def npm_scripts_blocked():
    """True / False, or None when npm isn't installed."""
    npm = shutil.which("npm")
    if not npm:
        return None
    code, out = run([npm, "config", "get", "ignore-scripts"], timeout=20)
    return code == 0 and out.strip().splitlines()[-1:] == ["true"]


_cache = {"at": 0.0, "value": None}
_cache_lock = threading.Lock()
CACHE_SECONDS = 10


def invalidate():
    """Forget the cached status (call after anything that changes protection)."""
    with _cache_lock:
        _cache["value"] = None


def protection():
    """Protection status, cached for a few seconds: it runs git and npm, and the UI asks often."""
    with _cache_lock:
        if _cache["value"] is not None and time.time() - _cache["at"] < CACHE_SECONDS:
            return _cache["value"]
    value = _protection()
    with _cache_lock:
        _cache.update(at=time.time(), value=value)
    return value


def _protection():
    installed = os.path.isfile(os.path.join(DEST, "checkrepo.py"))
    code, hooks_path = run(["git", "config", "--global", "--get", "core.hooksPath"], timeout=10)
    hooks_path = hooks_path.strip() if code == 0 else ""
    hooks = installed and same_path(hooks_path, os.path.join(DEST, "hooks"))
    return {
        "installed": installed,
        "up_to_date": installed and sha256(os.path.join(DEST, "checkrepo.py")) == sha256(os.path.join(KIT, "scanner", "checkrepo.py")),
        "hooks": hooks,
        "hooks_other": hooks_path if hooks_path and not hooks else "",
        "safeclone": in_shell_profile("safeclone"),
        "safeinstall": in_shell_profile("ArdvaneSafeInstall") or in_shell_profile("__ardvane_safe_install"),
        "npm": npm_scripts_blocked(),
        "editors": editors(),
        "routine": routine(),
        "launcher": launcher.installed(),
        "git": bool(shutil.which("git")),
    }
