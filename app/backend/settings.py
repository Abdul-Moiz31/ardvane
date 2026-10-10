"""User choices: GitHub account, hidden warnings, and the folders the daily check scans.

settings.json is also read by the daily-check scripts (GitHub check), and projects.txt is the same file the scripts
have always used for project folders, so the dashboard and the scripts never disagree.
"""
import json
import os
import re

from .config import DEFAULT_FOLDERS, DEST, PROJECTS, SETTINGS
from .system import read_json, write_private

GITHUB_USER_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
MAX_DISMISSED = 500
MAX_FOLDERS = 50


def load():
    s = read_json(SETTINGS, {})
    return {
        "github_enabled": bool(s.get("github_enabled")),
        "github_user": str(s.get("github_user") or ""),
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


def save_folders(folders):
    rows = [str(f).strip() for f in folders if str(f).strip()][:MAX_FOLDERS]
    for f in rows:
        if "\n" in f or not os.path.isdir(os.path.expanduser(f)):
            raise ValueError(f"folder not found: {f}")
    os.makedirs(DEST, exist_ok=True)
    with open(PROJECTS, "w", encoding="utf-8") as fh:
        fh.write("# Folders the daily check scans for git projects (one per line). Edited by the dashboard.\n")
        fh.write("".join(r + "\n" for r in rows))
