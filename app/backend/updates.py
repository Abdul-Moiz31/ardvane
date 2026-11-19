"""Updates from the dashboard: is a newer Ardvane available for the way it was installed, and install it.

  * The version offered is the one the install method would actually get: the Homebrew tap's formula, PyPI for
    pipx / pip, the latest GitHub release for a git clone. So Homebrew is never offered a release its tap doesn't
    have yet.
  * Checked at most every 12 hours while the dashboard is open (one download from GitHub or PyPI; nothing about this
    computer is sent), and only while "Check for updates" is on in Settings.
  * Updating runs fixed commands - never anything from the network - then refreshes the protection files and the
    daily check's fingerprints from the new version, and restarts the dashboard on it.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request

from . import actions, settings, status
from .config import DEST, INSTALLED, KIT, VERSION
from .system import kit_env, read_json, run, write_private

STATE = os.path.join(DEST, "update.json")
EVERY = 12 * 3600
REPO = "Abdul-Moiz31/ardvane"
TAP = "abdul-moiz31/ardvane/ardvane"
FORMULA_URL = "https://raw.githubusercontent.com/Abdul-Moiz31/homebrew-ardvane/main/Formula/ardvane.rb"
PYPI_URL = "https://pypi.org/pypi/ardvane/json"
RELEASES_URL = f"https://api.github.com/repos/{REPO}/releases?per_page=15"
VERSION_RE = re.compile(r"\d+\.\d+\.\d+")
_lock = threading.Lock()
_checking = threading.Event()


def as_tuple(v):
    return tuple(int(x) for x in v.split(".")) if v and VERSION_RE.fullmatch(v) else (0,)


def method():
    """How this copy was installed: 'brew', 'pipx', 'pip', 'git' or 'unknown'."""
    kit = KIT.replace("\\", "/")
    if INSTALLED and re.search(r"/(?:Cellar|opt)/ardvane(?:/|$)", kit):
        return "brew"
    if INSTALLED:
        return "pipx" if "/pipx/" in sys.prefix.replace("\\", "/") else "pip"
    if os.path.isdir(os.path.join(KIT, ".git")):
        return "git"
    return "unknown"


def _get(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "ardvane-update-check", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(2_000_000).decode("utf-8", "replace")


def latest_for(how):
    """The newest version this install method can install, or None."""
    if how == "brew":
        m = re.search(r'url "[^"]*/v(' + VERSION_RE.pattern + r')/', _get(FORMULA_URL))
        return m.group(1) if m else None
    if how in ("pipx", "pip"):
        v = json.loads(_get(PYPI_URL)).get("info", {}).get("version", "")
        return v if VERSION_RE.fullmatch(v) else None
    for r in json.loads(_get(RELEASES_URL)):
        tag = str(r.get("tag_name", ""))
        if not r.get("draft") and not r.get("prerelease") and re.fullmatch(r"v" + VERSION_RE.pattern, tag):
            return tag[1:]
    return None


def notes_between(current, latest):
    """[{version, notes}] of the releases newer than `current`, newest first (GitHub release notes, as markdown)."""
    out = []
    for r in json.loads(_get(RELEASES_URL)):
        tag = str(r.get("tag_name", ""))
        if re.fullmatch(r"v" + VERSION_RE.pattern, tag) and as_tuple(current) < as_tuple(tag[1:]) <= as_tuple(latest):
            out.append({"version": tag[1:], "notes": str(r.get("body") or "")[:8000]})
    return out


def check():
    """Ask the update source now and save the answer. Never raises: a failure is part of the state."""
    how = method()
    state = {"checked": time.time(), "method": how, "current": VERSION}
    try:
        latest = latest_for(how) if how != "unknown" else None
        state["latest"] = latest
        state["notes"] = notes_between(VERSION, latest) if latest and as_tuple(latest) > as_tuple(VERSION) else []
    except Exception as e:                                 # offline, rate-limited, a proxy: try again later
        state["error"] = f"couldn't check for updates ({e.__class__.__name__})"
    with _lock:
        write_private(STATE, json.dumps(state))
    return state


def _check_in_background():
    if _checking.is_set():
        return
    _checking.set()

    def go():
        try:
            check()
        finally:
            _checking.clear()
    threading.Thread(target=go, daemon=True).start()


def status_now():
    """What the dashboard shows. Starts a check in the background when the last one is old (never blocks a page)."""
    on = settings.load()["update_checks"]
    state = read_json(STATE, {})
    if on and time.time() - float(state.get("checked") or 0) > EVERY and not os.environ.get("ARDVANE_NO_UPDATE_CHECK"):
        _check_in_background()
    latest = state.get("latest") if isinstance(state.get("latest"), str) else None
    available = bool(on and latest and as_tuple(latest) > as_tuple(VERSION))
    how = method()
    able, what = can_update(how) if available else (False, "")
    notes = [n for n in state.get("notes", []) if isinstance(n, dict) and as_tuple(str(n.get("version"))) > as_tuple(VERSION)]
    return {"current": VERSION, "latest": latest, "available": available, "method": how, "checks": on,
            "checked": state.get("checked"), "error": state.get("error", ""), "checking": _checking.is_set(),
            "notes": notes if available else [], "can_update": able, "how": what}


# ---------------------------------------------------------------------------------------------- updating
def can_update(how):
    """(can the dashboard update itself?, what it does / what to run instead)."""
    if how == "brew":
        brew = shutil.which("brew") or next((p for p in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew") if os.path.isfile(p)), None)
        return (bool(brew), "Homebrew installs the new version (brew upgrade ardvane)" if brew else "run: brew upgrade ardvane")
    if how == "pipx":
        return (bool(shutil.which("pipx")), "pipx installs the new version (pipx upgrade ardvane)")
    if how == "git":
        code, out = run(["git", "-C", KIT, "status", "--porcelain"], timeout=20)
        _, branch = run(["git", "-C", KIT, "rev-parse", "--abbrev-ref", "HEAD"], timeout=20)
        if code == 0 and not out.strip() and branch.strip() == "main":
            return True, "git pulls the new version into " + KIT
        return False, f"your copy in {KIT} has local changes or isn't on main: run git pull there"
    if how == "pip":
        return False, "run: python3 -m pip install --upgrade ardvane"
    return False, "download the latest version from https://github.com/" + REPO


def upgrade_commands(how):
    if how == "brew":
        brew = shutil.which("brew") or next((p for p in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew") if os.path.isfile(p)), "brew")
        return [[brew, "update", "--quiet"], [brew, "upgrade", TAP]]
    if how == "pipx":
        return [[shutil.which("pipx") or "pipx", "upgrade", "ardvane"]]
    if how == "git":
        return [["git", "-C", KIT, "pull", "--ff-only", "origin", "main"]]
    return []


def apply():
    """Install the new version, then refresh the protection files and the daily check from it. (exit code, log)"""
    how = method()
    ok, why = can_update(how)
    if not ok:
        return 1, why
    log = []
    env = dict(os.environ, HOMEBREW_NO_AUTO_UPDATE="1", HOMEBREW_NO_INSTALL_CLEANUP="1", HOMEBREW_NO_ENV_HINTS="1")
    for cmd in upgrade_commands(how):
        code, out = run(cmd, timeout=900, env=env)
        log.append("$ " + " ".join(os.path.basename(cmd[0]) if i == 0 else c for i, c in enumerate(cmd)) + "\n" + out.strip())
        if code != 0:
            return code, "\n\n".join(log)
    # the kit folder now holds the new version: install its scanner, hooks and daily check over the old ones
    prot = status.protection()
    if prot.get("installed"):
        code, out = run(actions.installer_command("install"), timeout=600, env=kit_env())
        log.append("Protection updated" if code == 0 else "Updating protection failed:\n" + out.strip()[-2000:])
        if code != 0:
            return code, "\n\n".join(log)
        r = prot.get("routine") or {}
        if r.get("on") and r.get("time"):
            code, out = actions.set_routine(True, r["time"])
            log.append("Daily check re-registered" if code == 0 else "Re-registering the daily check failed:\n" + out.strip()[-1000:])
    status.invalidate()
    try:
        os.remove(STATE)                                    # the next check starts from the new version
    except OSError:
        pass
    return 0, "\n\n".join(log)


def restart_command():
    """How to start the dashboard again, on the version that is installed now."""
    if INSTALLED:
        exe = shutil.which("ardvane")
        if exe:
            return [exe, "--no-browser"]
    return [sys.executable, os.path.join(KIT, "app", "dashboard.py"), "--no-browser"]


def restart(port, token, shutdown):
    """Start the new version on the same port and key (so the open tab just reloads), then stop this one."""
    env = dict(os.environ, ARDVANE_PORT=str(port), ARDVANE_TOKEN=token, ARDVANE_RESTART_DELAY="2")
    kwargs = {"start_new_session": True} if os.name != "nt" else {"creationflags": getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    subprocess.Popen(restart_command(), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)
    threading.Timer(0.5, shutdown).start()
