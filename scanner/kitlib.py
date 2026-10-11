"""Helpers shared by the kit's standalone tools (github_check.py, autofix.py). Python 3.8+, standard library only.

The tools run from the repository (scanner/) and from the installed copy (~/.checkrepo), so files are looked up
next to this module first and in ~/.checkrepo second.
"""
import importlib.util
import json
import os
import sys
import tempfile

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


def write_atomic(path, data):
    """Write bytes atomically, readable only by this user. Each write uses its own temporary file, so two processes
    writing at the same moment can't collide, and a crash never leaves half a file."""
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=os.path.basename(path) + ".", suffix=".tmp")   # mode 0600
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def write_json(path, value):
    write_atomic(path, json.dumps(value, indent=1).encode("utf-8"))


def setting(key, default=None):
    return read_json(SETTINGS, {}).get(key, default)


def safe_output():
    """Never crash on emoji when output goes to a pipe with a legacy code page."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
