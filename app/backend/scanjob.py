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

from . import actions, detections
from .config import IS_WIN, KIT, SCANS
from .system import NO_WINDOW, kit_env, python_exe, run, short_hash

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


LISTED_OUTCOME = {"clean": "{n} branch(es) scanned", "found": "{n} branch(es) scanned", "unchanged": "unchanged since its last clean scan",
                  "scanned above": "scanned with your account", "error": "not scanned"}


def github_section(user, result, dismissed=(), repos=()):
    sec = {"title": "GitHub", "items": []}
    if result is None:
        return sec
    if result.get("error"):
        what = f"@{user}" if user else ", ".join(repos)
        sec["items"].append(item("warn", f"Couldn't check {what}: {result['error']}", key="0" * 16))
        return sec
    for sev, where, detail in result.get("findings", []):
        sec["items"].append(item("danger" if sev == "DANGER" else "warn", f"{where}: {detail}", dismissed=dismissed))
    level = "ok" if not result.get("findings") else "info"
    if user:
        sec["items"].append(item(level, f"@{result.get('user', user)}: {result.get('repos', 0)} repositories, "
                                 f"{len(result.get('recent', []))} pushed in the last 7 days, "
                                 f"{len(result.get('scanned', [])) - sum(1 for r in result.get('listed', []) if r.get('branches'))} scanned"
                                 + (f", {result['unchanged']} unchanged since their last clean scan" if result.get("unchanged") else "")))
    for r in result.get("listed", []):
        sec["items"].append(item(level, f"{r['repo']}: " + LISTED_OUTCOME.get(r["outcome"], r["outcome"]).format(n=r.get("branches", 0))))
    for note in result.get("notes", []):
        sec["items"].append(item("info", note))
    return sec


class ScanJob:
    def __init__(self, mode, folders, github_user, github_repos=(), on_finish=None, update_feed=False):
        self.id = secrets.token_hex(6)
        self.mode, self.folders, self.github_user, self.github_repos = mode, list(folders), github_user, list(github_repos)
        self.started, self.finished = time.time(), None
        self.events_file = os.path.join(tempfile.mkdtemp(prefix="polinrider-scan-"), "events.tsv")
        self.phase = "machine"
        self.proc = None
        self.cancelled = False
        self.github = None
        self.on_finish = on_finish
        self.update_feed, self.feed_note = update_feed, None
        self.autofixed = []
        self.lock = threading.Lock()
        threading.Thread(target=self._run, daemon=True).start()

    # -- running ---------------------------------------------------------------------------------------------
    def _machine_command(self):
        return actions.scan_command(self.mode == "quick", self.folders)

    def _start(self, cmd, **kw):
        with self.lock:
            if self.cancelled:
                return None
            self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, **kw)
            return self.proc

    def _run(self):
        try:
            if self.update_feed and not self.cancelled:     # newest signed detections first (a few seconds at most)
                self.phase = "feed"
                try:
                    self.feed_note = detections.update()["message"]
                except Exception as e:                       # never let the feed stop the scan itself
                    self.feed_note = f"Couldn't update detections ({e.__class__.__name__})"
                self.phase = "machine"
            os.makedirs(SCANS, exist_ok=True)
            env = kit_env(SCAN_EVENTS=self.events_file, SCAN_REPORT_DIR=SCANS)
            group = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | NO_WINDOW} if IS_WIN else {"start_new_session": True})
            p = self._start(self._machine_command(), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **group)
            if p:
                p.wait()
            if self.github_on and not self.cancelled:
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

    @property
    def github_on(self):
        return bool(self.github_user or self.github_repos)

    def _run_github(self):
        cmd = [python_exe(), os.path.join(KIT, "scanner", "github_check.py")] + ([self.github_user] if self.github_user else [])
        cmd += [a for r in self.github_repos for a in ("--repo", r)] + ["--json"]
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
        if self.github_on and (self.github is not None or self.phase == "github"):
            sections.append(github_section(self.github_user, self.github, set(dismissed), self.github_repos))
        items = [i for s in sections for i in s["items"]]
        total = len(MACHINE_STEPS) + (1 if self.github_on else 0)
        running = self.finished is None
        return {
            "id": self.id, "mode": self.mode, "running": running, "cancelled": self.cancelled, "phase": self.phase,
            "started": self.started, "finished": self.finished, "progress": progress, "code": code, "report": report,
            "steps_total": total, "steps_done": max(0, len(sections) - (1 if running else 0)),
            "sections": sections, "github_user": self.github_user,
            "github_repos": self.github_repos, "feed": self.feed_note, "folders": self.folders, "autofixed": self.autofixed,
            "danger": sum(1 for i in items if i["level"] == "danger"),
            "warn": sum(1 for i in items if i["level"] == "warn" and not i["dismissed"]),
            "ok": sum(1 for i in items if i["level"] == "ok"),
        }

    def reported_paths(self):
        return {i["path"] for s in self.state()["sections"] for i in s["items"] if i["path"]}
