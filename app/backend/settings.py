"""User choices: GitHub account and repositories, hidden warnings, and the folders the daily check scans.

settings.json is also read by the daily-check scripts (GitHub check), and projects.txt is the same file the scripts
have always used for project folders, so the dashboard and the scripts never disagree.
"""
import contextlib
import json
import os
import re
import threading

from . import kit
from .config import DEFAULT_FOLDERS, DEST, HOME, PROJECTS, SETTINGS
from .system import read_json, write_private

GITHUB_USER_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
MAX_DISMISSED = 500
MAX_FOLDERS = 50
MAX_REPOS = 100
AUTOFIX_MODES = ("ask", "auto", "all", "off")          # same as scanner/autofix.py MODES (a test keeps them equal)


_lock = threading.RLock()       # requests arrive on several threads; each change is load + modify + save


@contextlib.contextmanager
def editing():
    """Load settings, let the caller change them, save - as one step, so two requests can't undo each other's
    changes. Nothing is saved if the change raises."""
    with _lock:
        s = load()
        yield s
        save(s)


def change_list(current, change, clean):
    """A list after `change`: a whole new list, {"add": item} or {"remove": item}. Adding and removing apply to the
    saved list, so a page showing an out-of-date list can't drop entries. clean() checks and normalises."""
    if isinstance(change, list):
        return clean(change)
    if isinstance(change, dict) and list(change) == ["add"]:
        return clean(current + [change["add"]])
    if isinstance(change, dict) and list(change) == ["remove"]:
        return [x for x in current if x != change["remove"]]
    raise ValueError("expected a list, {add: ...} or {remove: ...}")


def load():
    s = read_json(SETTINGS, {})
    return {
        "autofix": s.get("autofix") if s.get("autofix") in AUTOFIX_MODES else "ask",
        "github_enabled": bool(s.get("github_enabled")),
        "github_user": str(s.get("github_user") or ""),
        "github_repos": _valid_repos(s.get("github_repos")),
        "feed_updates": s.get("feed_updates") is not False,              # on unless turned off
        "package_lookups": s.get("package_lookups") is not False,        # safe install asks OSV.dev too (on unless off)
        "dismissed": [d for d in s.get("dismissed", []) if isinstance(d, str)][-MAX_DISMISSED:],
    }


def save(s):
    write_private(SETTINGS, json.dumps(s, indent=2) + "\n")


def clean_github_user(value):
    """Normalised username, or raise ValueError."""
    user = str(value).strip().lstrip("@")
    if user and not GITHUB_USER_RE.fullmatch(user):
        raise ValueError("that doesn't look like a GitHub username")
    return user


def clean_github_repos(values):
    """Normalised 'owner/name' list (from names, github.com links or git@ addresses), or raise ValueError.
    Uses the GitHub check's own parser, so the dashboard accepts exactly what the check can scan."""
    if not isinstance(values, list):
        raise ValueError("repositories must be a list")
    out = []
    for v in values:
        name = kit.module("github_check").parse_repo(v)
        if name.lower() not in {r.lower() for r in out}:
            out.append(name)
    if len(out) > MAX_REPOS:
        raise ValueError(f"at most {MAX_REPOS} repositories")
    return out


def _valid_repos(values):
    """The saved list, keeping only entries that are still valid (the file can be edited by hand)."""
    parse = kit.module("github_check").parse_repo
    out = []
    for v in values if isinstance(values, list) else []:
        try:
            out.append(parse(v))
        except ValueError:
            pass
    return out[:MAX_REPOS]


def set_dismissed(s, key, hidden):
    if hidden and key not in s["dismissed"]:
        s["dismissed"].append(key)
    elif not hidden:
        s["dismissed"] = [k for k in s["dismissed"] if k != key]


def folder_path(f):
    """Where a listed folder is on disk (~ expanded, normalised)."""
    return os.path.normpath(os.path.expanduser(str(f).strip()))


def tidy_folder(f):
    """A folder as it is stored and shown: ~/... inside your home folder, else the full path. ValueError if it can't
    be a folder path at all (relative, several lines)."""
    f = str(f).strip()
    if not f or any(c in f for c in "\n\r\0"):
        raise ValueError("enter a folder path, for example ~/code")
    p = folder_path(f)
    if not os.path.isabs(p):
        raise ValueError(f"use a full path, for example ~/{f}")
    if "#" in f:
        raise ValueError("a folder path with # in it can't be saved (# starts a comment in projects.txt)")
    if p == HOME or p.startswith(HOME + os.sep):
        return "~" + p[len(HOME):]
    return p


def load_folders():
    """(folders, customised?) - folders the daily check and "My project folders" scans search for git projects.
    Without a saved list these are the defaults that exist on this computer (the scripts skip the others too)."""
    try:
        with open(PROJECTS, encoding="utf-8") as f:
            rows = [line.split("#", 1)[0].strip() for line in f]
        return [r for r in rows if r], True
    except OSError:
        return [tidy_folder(d) for d in DEFAULT_FOLDERS if os.path.isdir(folder_path(d))], False


def folder_info(folders):
    """Each listed folder with whether it is still there, for the dashboard."""
    return [{"path": f, "exists": os.path.isdir(folder_path(f))} for f in folders]


def change_folders(change):
    """The folder list after {"add": path}, {"remove": path}, {"reset": true} or a whole new list, saved. A new folder
    must exist; folders already listed stay even if they're gone for now (an unplugged drive), and can always be
    removed. Paths are compared as folders, so ~/code, /Users/you/code and ~/code/ are the same entry."""
    current, _ = load_folders()
    if isinstance(change, dict) and change == {"reset": True}:
        try:
            os.remove(PROJECTS)          # the scripts and the dashboard fall back to the defaults
        except FileNotFoundError:
            pass
        return load_folders()[0]
    if isinstance(change, dict) and list(change) == ["add"]:
        new = [change["add"]]
        rows = current + new
    elif isinstance(change, dict) and list(change) == ["remove"]:
        gone = folder_path(change["remove"])
        new, rows = [], [f for f in current if folder_path(f) != gone]
    elif isinstance(change, list):
        new, rows = [f for f in change if folder_path(f) not in {folder_path(c) for c in current}], change
    else:
        raise ValueError("expected a list, {add: ...}, {remove: ...} or {reset: true}")
    for f in new:
        if not os.path.isdir(folder_path(tidy_folder(f))):
            raise ValueError(f"folder not found: {str(f).strip()}")
    out, seen = [], set()
    for f in rows:
        t = tidy_folder(f)
        if folder_path(t) not in seen:
            seen.add(folder_path(t))
            out.append(t)
    if len(out) > MAX_FOLDERS:
        raise ValueError(f"at most {MAX_FOLDERS} folders")
    save_folders(out)
    return out


def save_folders(rows):
    os.makedirs(DEST, exist_ok=True)
    with open(PROJECTS, "w", encoding="utf-8") as fh:
        fh.write("# Folders the daily check scans for git projects (one per line). Edited by the dashboard.\n")
        fh.write("".join(r + "\n" for r in rows))
