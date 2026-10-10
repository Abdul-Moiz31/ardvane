"""A machine scan (scan-my-machine.sh / .ps1) plus the optional GitHub check, run in the background.

The scan scripts append one tab-separated line per result to $SCAN_EVENTS:
    TYPE <tab> message <tab> path      TYPE: H section, D danger, W check, O ok, I info, P progress, R result
This module turns those lines into sections and findings for the dashboard.
"""
import json
import os
import re
import secrets
import signal
import subprocess
import tempfile
import threading
import time

from .config import IS_WIN, KIT, SCANS
from .system import NO_WINDOW, python_exe, run, short_hash

MACHINE_STEPS = ["Known malware locations", "Running processes", "Programs that start automatically",
                 "Shell startup files and hosts file", "Connections to known attacker servers",
                 "Code editor settings and extensions", "Your projects", "Known malicious packages", "Built-in protections"]
LEVELS = {"D": "danger", "W": "warn", "O": "ok", "I": "info"}


def item(level, text, path="", key=None, dismissed=()):
    key = key or short_hash(text)
    return {"level": level, "text": text, "path": path, "key": key,
            "dismissed": level == "warn" and key in dismissed}


def parse_events(lines, dismissed=()):
    """(sections, progress text, exit code, report path) from the scan script's event lines."""
    sections, current, progress, code, report = [], None, None, None, None
    for line in lines:
        kind, msg, path = (line.split("\t") + ["", ""])[:3]
        if kind == "H":
            current = {"title": re.sub(r"^\d+\.\s*", "", msg), "items": []}
            sections.append(current)
        elif kind in LEVELS and current is not None:
            current["items"].append(item(LEVELS[kind], msg, path, dismissed=dismissed))
        elif kind == "P":
            progress = msg
        elif kind == "R":
            code = int(msg) if msg.lstrip("-").isdigit() else None
            report = path or None
    return sections, progress, code, report


def github_section(user, result, dismissed=()):
    sec = {"title": "GitHub account", "items": []}
    if result is None:
        return sec
    if result.get("error"):
        sec["items"].append(item("warn", f"Couldn't check @{user}: {result['error']}", key="0" * 16))
        return sec
    for sev, where, detail in result.get("findings", []):
        sec["items"].append(item("danger" if sev == "DANGER" else "warn", f"{where}: {detail}", dismissed=dismissed))
    summary = (f"@{result.get('user', user)}: {result.get('repos', 0)} repositories, {len(result.get('recent', []))} pushed "
               f"in the last 7 days, {len(result.get('scanned', []))} scanned"
               + (f", {result['unchanged']} unchanged since their last clean scan" if result.get("unchanged") else ""))
    sec["items"].append(item("ok" if not result.get("findings") else "info", summary))
    for note in result.get("notes", []):
        sec["items"].append(item("info", note))
    return sec


class ScanJob:
    def __init__(self, mode, folders, github_user, on_finish=None):
        self.id = secrets.token_hex(6)
        self.mode, self.folders, self.github_user = mode, list(folders), github_user
        self.started, self.finished = time.time(), None
        self.events_file = os.path.join(tempfile.mkdtemp(prefix="polinrider-scan-"), "events.tsv")
        self.phase = "machine"
        self.proc = None
        self.cancelled = False
        self.github = None
        self.on_finish = on_finish
        self.autofixed = []
        self.lock = threading.Lock()
        threading.Thread(target=self._run, daemon=True).start()

    # -- running ---------------------------------------------------------------------------------------------
    def _machine_command(self):
        if IS_WIN:
            return (["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", os.path.join(KIT, "scan-my-machine.ps1")]
                    + (["-Quick"] if self.mode == "quick" else []) + self.folders)
        return ["bash", os.path.join(KIT, "scan-my-machine.sh")] + (["--quick"] if self.mode == "quick" else []) + self.folders

    def _start(self, cmd, **kw):
        with self.lock:
            if self.cancelled:
                return None
            self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, **kw)
            return self.proc

    def _run(self):
        try:
            os.makedirs(SCANS, exist_ok=True)
            env = dict(os.environ, SCAN_EVENTS=self.events_file, SCAN_REPORT_DIR=SCANS)
            group = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | NO_WINDOW} if IS_WIN else {"start_new_session": True})
            p = self._start(self._machine_command(), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **group)
            if p:
                p.wait()
            if self.github_user and not self.cancelled:
                self.phase = "github"
                self._run_github()
            if self.on_finish and not self.cancelled:
                self.phase = "fixing"
                self.autofixed = self.on_finish(self) or []
        except OSError as e:
            with open(self.events_file, "a", encoding="utf-8") as f:
                f.write(f"H\tScan\t\nW\tThe scan could not start: {e}\t\n")
        finally:
            self.finished = time.time()
            self.phase = "done"

    def _run_github(self):
        cmd = [python_exe(), os.path.join(KIT, "scanner", "github_check.py"), self.github_user, "--json"]
        p = self._start(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=NO_WINDOW)
        if not p:
            return
        out, _ = p.communicate()
        try:
            self.github = json.loads(out.decode("utf-8", "replace") or "{}")
        except ValueError:
            self.github = {}
        if not self.github and not self.cancelled:
            self.github = {"error": "the GitHub check did not finish"}

    def cancel(self):
        with self.lock:
            self.cancelled = True
            p = self.proc
        if p is None or p.poll() is not None:
            return
        try:
            if IS_WIN:
                run(["taskkill", "/T", "/F", "/PID", str(p.pid)], timeout=20)
            elif self.phase == "machine":
                os.killpg(p.pid, signal.SIGTERM)     # the scan script and everything it started
            else:
                p.terminate()
        except (OSError, ProcessLookupError):
            pass

    # -- reporting -------------------------------------------------------------------------------------------
    def state(self, dismissed=()):
        try:
            with open(self.events_file, encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError:
            lines = []
        sections, progress, code, report = parse_events(lines, set(dismissed))
        if self.github_user and (self.github is not None or self.phase == "github"):
            sections.append(github_section(self.github_user, self.github, set(dismissed)))
        items = [i for s in sections for i in s["items"]]
        total = len(MACHINE_STEPS) + (1 if self.github_user else 0)
        running = self.finished is None
        return {
            "id": self.id, "mode": self.mode, "running": running, "cancelled": self.cancelled, "phase": self.phase,
            "started": self.started, "finished": self.finished, "progress": progress, "code": code, "report": report,
            "steps_total": total, "steps_done": max(0, len(sections) - (1 if running else 0)),
            "sections": sections, "github_user": self.github_user, "folders": self.folders, "autofixed": self.autofixed,
            "danger": sum(1 for i in items if i["level"] == "danger"),
            "warn": sum(1 for i in items if i["level"] == "warn" and not i["dismissed"]),
            "ok": sum(1 for i in items if i["level"] == "ok"),
        }

    def reported_paths(self):
        return {i["path"] for s in self.state()["sections"] for i in s["items"] if i["path"]}
