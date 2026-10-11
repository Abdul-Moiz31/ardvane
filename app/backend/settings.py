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
from .config import DEFAULT_FOLDERS, DEST, PROJECTS, SETTINGS
from .system import read_json, write_private

GITHUB_USER_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
MAX_DISMISSED = 500
MAX_FOLDERS = 50
MAX_REPOS = 100
AUTOFIX_MODES = ("ask", "auto", "off")          # same as scanner/autofix.py MODES (a test keeps them equal)


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


def load_folders():
    """(folders, customised?) — folders the daily check searches for git projects."""
    try:
        with open(PROJECTS, encoding="utf-8") as f:
            rows = [line.split("#", 1)[0].strip() for line in f]
        return [r for r in rows if r], True
    except OSError:
        return list(DEFAULT_FOLDERS), False


def clean_folders(folders):
    """Folders that exist, without duplicates, or raise ValueError."""
    if not isinstance(folders, list):
        raise ValueError("folders must be a list")
    rows = []
    for f in (str(f).strip() for f in folders):
        if f and f not in rows:
            rows.append(f)
    for f in rows:
        if "\n" in f or not os.path.isdir(os.path.expanduser(f)):
            raise ValueError(f"folder not found: {f}")
    return rows[:MAX_FOLDERS]


def save_folders(folders):
    rows = clean_folders(folders)
    os.makedirs(DEST, exist_ok=True)
    with open(PROJECTS, "w", encoding="utf-8") as fh:
        fh.write("# Folders the daily check scans for git projects (one per line). Edited by the dashboard.\n")
        fh.write("".join(r + "\n" for r in rows))
