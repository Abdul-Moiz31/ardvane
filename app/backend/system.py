"""Small, safe wrappers around processes and files."""
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ANSI = re.compile(r"\x1b\[[0-9;]*m")
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)       # Windows: don't flash a console window


def run(cmd, timeout=60, env=None):
    """Run a command given as a list (never through a shell). Returns (exit code, output without colour codes)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, encoding="utf-8",
                           errors="replace", stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
        return r.returncode, ANSI.sub("", (r.stdout or "") + (r.stderr or ""))
    except (OSError, subprocess.SubprocessError) as e:
        return -1, str(e)


def powershell_command(script, *args):
    return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, *args]


def powershell(script, *args, timeout=600, env=None):
    return run(powershell_command(script, *args), timeout, env)


def python_exe():
    return sys.executable or shutil.which("python3") or "python3"


def read_json(path, default):
    """JSON from a file, or `default` when it's missing, unreadable or of a different type."""
    try:
        with open(path, encoding="utf-8") as f:
            value = json.load(f)
        return value if isinstance(value, type(default)) else default
    except (OSError, ValueError):
        return default


def write_private(path, text):
    """Atomically write a file that only the current user can read. Each write uses its own temporary file, so two
    writes at the same moment can't collide (the later one simply wins)."""
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=os.path.basename(path) + ".", suffix=".tmp")   # mode 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise


def read_text(path, limit=2_000_000):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return None


def sha256(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def short_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def same_path(a, b):
    if not a or not b:
        return False

    def norm(p):
        return os.path.normcase(os.path.normpath(os.path.expanduser(p.strip().strip('"'))))
    return norm(a) == norm(b)
