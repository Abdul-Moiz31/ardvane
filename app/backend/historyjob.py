"""History scans and history cleanups for the dashboard, run in the background (scanner/history.py does the work).

  scan  PATH | OWNER/NAME   read-only: every commit, branch and tag
  clean OWNER/NAME          prepares a clean history (backup + rewrite + verify); nothing is pushed
  push  WORKDIR             pushes a prepared clean history, after a person confirmed it
"""
import json
import os
import re
import secrets
import subprocess
import threading
import time

from . import kit
from .config import DEST, KIT
from .system import NO_WINDOW, kit_env, python_exe, run

WORK_ROOT = os.path.join(DEST, "history")
REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")


def github_name(path):
    """owner/name of a local repository's GitHub remote ('origin'), or ''."""
    code, url = run(["git", "-c", "core.fsmonitor=false", "-C", path, "remote", "get-url", "origin"], timeout=15)
    if code != 0:
        return ""
    try:
        return kit.module("github_check").parse_repo(url.strip())
    except (ValueError, Exception):
        return ""


def check_target(action, target):
    """The validated target for an action, or ValueError. Nothing from a request reaches git unchecked."""
    target = str(target or "").strip()
    if action == "scan":
        path = os.path.abspath(os.path.expanduser(target))
        if os.path.isdir(path) and os.path.exists(os.path.join(path, ".git")):
            return path
        if REPO_RE.match(target):
            return target
        raise ValueError("choose a local repository folder or a GitHub repository (owner/name)")
    if action == "clean":
        if REPO_RE.match(target):
            return target
        raise ValueError("only a GitHub repository (owner/name) can have its history cleaned")
    if action == "push":
        path = os.path.realpath(target)
        if path.startswith(os.path.realpath(WORK_ROOT) + os.sep) and os.path.isfile(os.path.join(path, "plan.json")):
            return path
        raise ValueError("unknown clean history")
    raise ValueError("unknown action")


class HistoryJob:
    def __init__(self, action, target):
        self.id = secrets.token_hex(6)
        self.action, self.target = action, target
        self.started, self.finished = time.time(), None
        self.phase, self.progress, self.result, self.error = "starting", None, None, ""
        self.proc = None
        self.lock = threading.Lock()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        cmd = [python_exe(), os.path.join(KIT, "scanner", "history.py"), self.action, self.target, "--json"]
        try:
            self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         env=kit_env(), creationflags=NO_WINDOW)
            out = []
            reader = threading.Thread(target=lambda: out.append(self.proc.stdout.read()), daemon=True)
            reader.start()
            for raw in self.proc.stderr:                        # progress: one JSON object per line
                try:
                    ev = json.loads(raw.decode("utf-8", "replace"))
                except ValueError:
                    continue
                if ev.get("event") == "phase":
                    self.phase = str(ev.get("text", ""))[:200]
                elif ev.get("event") == "progress":
                    self.progress = [int(ev.get("done", 0)), int(ev.get("total", 0))]
            self.proc.wait()
            reader.join(timeout=10)
            text = (out[0] if out else b"").decode("utf-8", "replace").strip()
            data = json.loads(text) if text else {}
            if "error" in data:
                self.error = str(data["error"])
            else:
                self.result = data
        except (OSError, ValueError) as e:
            self.error = f"could not run ({e.__class__.__name__}: {e})"
        finally:
            self.finished = time.time()
            self.phase = "done"

    def cancel(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    def state(self):
        res = self.result
        if res and self.action == "scan" and "findings" in res:
            # offer a cleanup for a GitHub repository, or a local clone of one (looked up once)
            if "github" not in res:
                res["github"] = self.target if REPO_RE.match(self.target) else github_name(self.target)
        return {"id": self.id, "action": self.action, "target": self.target, "running": self.finished is None,
                "started": self.started, "finished": self.finished, "phase": self.phase, "progress": self.progress,
                "result": res, "error": self.error}
