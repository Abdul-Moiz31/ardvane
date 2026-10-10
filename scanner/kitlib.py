"""Helpers shared by the kit's standalone tools (github_check.py, autofix.py). Python 3.8+, standard library only.

The tools run from the repository (scanner/) and from the installed copy (~/.checkrepo), so files are looked up
next to this module first and in ~/.checkrepo second.
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")
DEST = os.path.join(HOME, ".checkrepo")
SETTINGS = os.path.join(DEST, "settings.json")
IS_WIN = os.name == "nt"
IS_MAC = sys.platform == "darwin"


def find(*names):
    """First existing file among <here>/<names...> and ~/.checkrepo/<last name>."""
    for p in (os.path.join(HERE, *names), os.path.join(DEST, names[-1])):
        if os.path.isfile(p):
            return p
    return None


def load_checkrepo():
    path = find("checkrepo.py")
    if not path:
        raise SystemExit("checkrepo.py not found")
    spec = importlib.util.spec_from_file_location("checkrepo", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            value = json.load(f)
        return value if isinstance(value, type(default)) else default
    except (OSError, ValueError):
        return default


def write_json(path, value):
    """Atomic write, readable only by this user."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(value, f, indent=1)
    os.replace(tmp, path)


def setting(key, default=None):
    return read_json(SETTINGS, {}).get(key, default)


def safe_output():
    """Never crash on emoji when output goes to a pipe with a legacy code page."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
