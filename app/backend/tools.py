"""The four tools added in 0.12, as the dashboard uses them: block force pushes, tell the owner, open safely, secrets.

The work is done by the same scripts the command line runs (scanner/github_protect.py, report_owner.py, sandbox.py,
credaudit.py), loaded through `kit`, so there is one implementation of each.
"""
import os
import shlex
import shutil
import subprocess
import threading
import time

from . import kit
from .config import DEST, IS_MAC, IS_WIN, INSTALLED, KIT
from .system import python_exe, write_private


# ------------------------------------------------------------------------------------------ tell the owner
class ReportJob:
    """Scan one repository and build the report for its owner, in the background (a big repository takes minutes)."""

    def __init__(self, repo):
        self.repo, self.started, self.finished = repo, time.time(), None
        self.result, self.error = None, None
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            self.result = kit.module("report_owner").make(self.repo)
        except Exception as e:                        # shown to the user; never a traceback
            self.error = str(e)[:300] or e.__class__.__name__
        self.finished = time.time()

    def state(self):
        r = self.result
        return {"repo": self.repo, "running": self.finished is None, "error": self.error,
                "result": None if r is None else dict({k: r[k] for k in ("repo", "public", "clean", "branches", "report", "link", "can_issue")},
                                                      findings=len(r["findings"]))}


# ------------------------------------------------------------------------------------------ open safely
_runtime = {"at": 0.0, "value": (None, False, "")}


def sandbox_runtime():
    """(docker | podman | None, ready, message), remembered for a minute: asking the engine takes a second."""
    if time.time() - _runtime["at"] > 60:
        _runtime["value"], _runtime["at"] = kit.module("sandbox").runtime(), time.time()
    return _runtime["value"]


def sandbox_command(target):
    """The command that opens `target` in the sandbox, as a list: validated first, so only a real owner/name or an existing folder gets in."""
    kind, spec = kit.module("sandbox").parse_target(target)
    base = ["ardvane"] if INSTALLED and shutil.which("ardvane") else [python_exe(), os.path.join(KIT, "app", "dashboard.py")]
    return kind, spec, base + ["sandbox", spec]


def open_in_terminal(argv):
    """Open a terminal window running `argv` (the sandbox needs a real terminal for its shell). True if one was opened."""
    line = " ".join(shlex.quote(a) for a in argv)
    if IS_MAC:
        folder = os.path.join(DEST, "launch")
        path = os.path.join(folder, f"sandbox-{int(time.time())}.command")
        write_private(path, f'#!/bin/bash\nrm -f -- "$0"\nclear\n{line}\necho\nread -r -p "Press Return to close this window. " _\n')
        os.chmod(path, 0o700)
        return subprocess.call(["open", "-a", "Terminal", path]) == 0
    if IS_WIN:
        subprocess.Popen(argv, creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
        return True
    for term, args in (("x-terminal-emulator", ["-e"]), ("gnome-terminal", ["--"]), ("konsole", ["-e"]), ("xterm", ["-e"])):
        exe = shutil.which(term)
        if exe:
            subprocess.Popen([exe, *args, "bash", "-c", f"{line}; read -r -p 'Press Return to close. ' _"], start_new_session=True)
            return True
    return False
