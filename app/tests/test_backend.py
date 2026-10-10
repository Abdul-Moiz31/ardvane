"""Tests for the dashboard backend.  Run:  python3 app/tests/test_backend.py

Uses a throw-away home folder, so nothing on this computer is touched. Standard library only.
"""
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

SANDBOX = tempfile.mkdtemp(prefix="dashboard-test-")
os.environ["HOME"] = os.environ["USERPROFILE"] = SANDBOX          # must be set before the backend is imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import config, docs, reports, scanjob, settings, tasks    # noqa: E402
from backend.server import App, Handler                            # noqa: E402
import http.server                                                 # noqa: E402


class ParseEvents(unittest.TestCase):
    def test_sections_findings_progress_and_result(self):
        lines = ["H\t1. Known malware locations\t", "D\tfound: ~/.n2\t/home/x/.n2", "H\t2. Running processes\t",
                 "O\tnothing suspicious\t", "W\tinline node process\t", "P\t3 ~/code/app\t", "R\t1\t/tmp/report.txt"]
        sections, progress, code, report = scanjob.parse_events(lines)
        self.assertEqual([s["title"] for s in sections], ["Known malware locations", "Running processes"])
        self.assertEqual(sections[0]["items"][0]["level"], "danger")
        self.assertEqual(sections[0]["items"][0]["path"], "/home/x/.n2")
        self.assertEqual((progress, code, report), ("3 ~/code/app", 1, "/tmp/report.txt"))

    def test_dismissed_applies_to_warnings_only(self):
        w = scanjob.item("warn", "x")
        d = scanjob.item("danger", "y")
        sections, *_ = scanjob.parse_events(["H\tS\t", "W\tx\t", "D\ty\t"], {w["key"], d["key"]})
        self.assertTrue(sections[0]["items"][0]["dismissed"])
        self.assertFalse(sections[0]["items"][1]["dismissed"], "a DANGER can never be hidden")

    def test_events_before_a_section_and_garbage_are_ignored(self):
        sections, progress, code, report = scanjob.parse_events(["D\torphan\t", "", "nonsense", "R\tx\t"])
        self.assertEqual((sections, code), ([], None))

    def test_github_section(self):
        sec = scanjob.github_section("me", {"user": "me", "repos": 3, "recent": [], "scanned": [], "findings": [["DANGER", "me/r", "bad"]], "notes": ["n"]})
        self.assertEqual([i["level"] for i in sec["items"]], ["danger", "info", "info"])
        self.assertEqual(scanjob.github_section("me", {"error": "offline"})["items"][0]["level"], "warn")


class ScanJobHooks(unittest.TestCase):
    def test_on_finish_runs_after_a_successful_scan(self):
        calls = []
        job = scanjob.ScanJob.__new__(scanjob.ScanJob)
        job.__init__("quick", [], "", on_finish=lambda j: calls.append(j) or [{"title": "x", "ok": True}])
        deadline = time.time() + 120
        while job.finished is None and time.time() < deadline:
            time.sleep(0.2)
        self.assertEqual(len(calls), 1, "the hook runs once, after the scan")
        self.assertEqual(job.state()["autofixed"], [{"title": "x", "ok": True}])


class Reports(unittest.TestCase):
    def setUp(self):
        os.makedirs(config.SCANS, exist_ok=True)
        with open(os.path.join(config.REPORTS, "2026-01-02.txt"), "w", encoding="utf-8") as f:
            f.write("VERDICT: Clean, 2 item(s) worth a look\n\n  ⚠️  a\n  ⚠️  b\n")
        with open(os.path.join(config.SCANS, "scan-report-2026-01-03-0900.txt"), "w", encoding="utf-8") as f:
            f.write("x\n  [DANGER] found: y\nRESULT: INFECTED - 1 serious finding(s).\n")

    def test_list_and_summaries(self):
        rows = {r["id"]: r for r in reports.list_all()}
        self.assertEqual((rows["daily:2026-01-02.txt"]["level"], rows["daily:2026-01-02.txt"]["warn"]), ("warn", 2))
        self.assertEqual((rows["scan:scan-report-2026-01-03-0900.txt"]["level"], rows["scan:scan-report-2026-01-03-0900.txt"]["danger"]), ("danger", 1))

    def test_only_known_report_names_can_be_read(self):
        self.assertIsNotNone(reports.read("daily:2026-01-02.txt"))
        for bad in ("daily:../settings.json", "scan:../../.ssh/id_rsa", "other:2026-01-02.txt", "daily:2026-01-02.txt/../x", ""):
            self.assertIsNone(reports.read(bad), bad)


class Settings(unittest.TestCase):
    def test_github_usernames(self):
        self.assertEqual(settings.clean_github_user(" @Abdul-Moiz31 "), "Abdul-Moiz31")
        for bad in ("a/b", "-x", "x-", "a b", "x" * 40, "../etc"):
            with self.assertRaises(ValueError, msg=bad):
                settings.clean_github_user(bad)

    def test_folders_must_exist(self):
        with self.assertRaises(ValueError):
            settings.save_folders(["/definitely/not/here"])
        settings.save_folders([SANDBOX])
        self.assertEqual(settings.load_folders(), ([SANDBOX], True))


class Tasks(unittest.TestCase):
    """The to-do list: findings become steps, fixes are verified by later checks, habits come back."""

    PROTECTION_OFF = {"installed": False, "hooks": False, "routine": {"on": False}}
    PROTECTION_ON = {"installed": True, "hooks": True, "routine": {"on": True}}

    def setUp(self):
        if os.path.exists(config.TASKS):
            os.remove(config.TASKS)

    def view(self, data, tid):
        return next(t for t in tasks.overview(data, now=self.now)["tasks"] if t["id"] == tid)

    now = 1_800_000_000

    def test_danger_creates_finding_task_and_recovery_checklist(self):
        f = tasks.finding("danger", "INFECTED: ~/code/x — .gitignore: hides the worm's push scripts", "/x", seen=self.now)
        data = tasks.sync([f], self.PROTECTION_OFF, set(), now=self.now)
        view = self.view(data, "f-" + f["key"])
        self.assertEqual((view["title"], view["level"], view["status"]), ("Remove the infected project", "danger", "open"))
        counts = tasks.overview(data, now=self.now)["counts"]
        self.assertEqual((counts["incident_total"], counts["incident_done"]), (7, 0))

    def test_fixed_task_reopens_when_a_later_check_still_finds_it(self):
        f = tasks.finding("danger", "found: ~/.n2", seen=self.now)
        tid = "f-" + f["key"]
        tasks.sync([f], self.PROTECTION_OFF, set(), now=self.now)
        tasks.set_done(tid, True)
        data = tasks.sync([dict(f, seen=self.now - 10)], self.PROTECTION_OFF, set(), now=self.now)   # older report: no change
        self.assertEqual(self.view(data, tid)["status"], "done")
        data = tasks.sync([dict(f, seen=4_000_000_000)], self.PROTECTION_OFF, set(), now=self.now)  # newer check still finds it
        v = self.view(data, tid)
        self.assertEqual(v["status"], "open")
        self.assertIn("still found it", v["reopened"])

    def test_hidden_warning_closes_its_task_and_creates_none(self):
        w = tasks.finding("warn", "editor extension installed/updated in last 24h: x.y", seen=self.now)
        data = tasks.sync([w], self.PROTECTION_OFF, {w["key"]}, now=self.now)
        self.assertNotIn("f-" + w["key"], data["tasks"])
        tasks.sync([w], self.PROTECTION_OFF, set(), now=self.now)
        data = tasks.sync([w], self.PROTECTION_OFF, {w["key"]}, now=self.now)
        self.assertEqual(self.view(data, "f-" + w["key"])["resolution"], "mine")
        self.assertEqual(self.view(data, "f-" + w["key"])["title"], "Check a new editor extension")

    def test_setup_tasks_follow_protection_status(self):
        data = tasks.sync([], self.PROTECTION_ON, set(), now=self.now)
        self.assertEqual(self.view(data, "setup-protection")["resolution"], "auto")
        data = tasks.sync([], self.PROTECTION_OFF, set(), now=self.now)
        self.assertEqual(self.view(data, "setup-protection")["status"], "open", "switched off again: back on the list")

    def test_routine_checks_come_back(self):
        tasks.sync([], self.PROTECTION_OFF, set(), now=self.now)
        tasks.set_done("weekly-security-log", True)
        data = tasks._load()
        self.assertEqual(tasks._view("weekly-security-log", data["tasks"]["weekly-security-log"], time.time())["status"], "scheduled")
        self.assertEqual(tasks._view("weekly-security-log", data["tasks"]["weekly-security-log"], time.time() + 8 * 86400)["status"], "open")

    def test_removing_malware_opens_the_recovery_checklist_once(self):
        tasks.sync([], self.PROTECTION_OFF, set(), now=self.now)
        tasks.start_incident()
        tasks.start_incident()
        data = tasks._load()
        self.assertEqual(tasks.overview(data)["counts"]["incident_total"], 7)
        self.assertTrue(all(not data["tasks"][t["id"]]["done_at"] for t in tasks.INCIDENT))

    def test_steps_are_validated(self):
        tasks.sync([], self.PROTECTION_OFF, set(), now=self.now)
        tasks.set_step("weekly-access", 1, True)
        self.assertEqual(tasks._load()["tasks"]["weekly-access"]["steps_done"], [1])
        with self.assertRaises(KeyError):
            tasks.set_step("weekly-access", 99, True)
        with self.assertRaises(KeyError):
            tasks.set_step("no-such-task", 0, True)

    def test_report_lines_become_findings_with_the_same_key_as_scan_events(self):
        self.assertEqual(reports.findings("  🛑 found: ~/.n2\n  ⚠️  hosts file has custom entries\n  [CHECK]  x\n  ✅ none"),
                         [("danger", "found: ~/.n2"), ("warn", "hosts file has custom entries"), ("warn", "x")])
        self.assertEqual(tasks.finding("danger", "found: ~/.n2")["key"], scanjob.item("danger", "found: ~/.n2")["key"])


class Fixes(unittest.TestCase):
    def test_modes_match_the_fixer(self):
        from backend import fixes
        self.assertEqual(settings.AUTOFIX_MODES, fixes.autofix().MODES)
        self.assertEqual(settings.load()["autofix"], fixes.autofix().DEFAULT_MODE)

    def test_fix_api_refuses_unknown_ids_and_bad_modes(self):
        from backend import server
        with self.assertRaises(server.ApiError):
            server.post_fix({"id": "path:000000000000"})
        with self.assertRaises(server.ApiError):
            server.post_settings({"autofix": "everything"})
        with self.assertRaises(server.ApiError):
            server.post_unfix({"id": "nope"})


class FolderPicker(unittest.TestCase):
    """The native picker is replaced by a fake: tests must never open a dialog on the screen."""

    def pick(self, code, out):
        from backend import actions
        if actions._picker_command() is None:
            self.skipTest("no folder picker on this system")
        return actions.pick_folder(runner=lambda cmd, timeout: (code, out))

    def test_picked_folder_inside_home_is_shortened(self):
        os.makedirs(os.path.join(SANDBOX, "code"), exist_ok=True)
        self.assertEqual(self.pick(0, os.path.join(SANDBOX, "code") + os.sep + "\n"), {"path": os.path.join("~", "code")})

    def test_cancel_and_garbage_are_ignored(self):
        self.assertEqual(self.pick(1, "execution error: User canceled. (-128)"), {"cancelled": True})
        self.assertEqual(self.pick(0, "relative/path"), {"cancelled": True})
        self.assertEqual(self.pick(0, "/definitely/not/a/folder"), {"cancelled": True})


class Commands(unittest.TestCase):
    """The `ardvane` command line and the shared command builders."""

    def test_version_help_and_unknown(self):
        from backend import cli
        self.assertEqual(cli.main(["--version"]), 0)
        self.assertEqual(cli.main(["--help"]), 0)
        self.assertEqual(cli.main(["definitely-not-a-command"]), 3)
        self.assertTrue({"scan", "check", "protect", "unprotect", "fixes", "launcher"} <= set(cli.COMMANDS))

    def test_command_builders(self):
        from backend import actions
        self.assertIn("--quick" if os.name != "nt" else "-Quick", actions.scan_command(True, ["/x"]))
        self.assertEqual(actions.scan_command(False, ["/x"])[-1], "/x")
        self.assertIn("--dry-run" if os.name != "nt" else "-DryRun", actions.installer_command("install", True))
        self.assertNotIn("--dry-run", actions.installer_command("uninstall", True))
        with self.assertRaises(ValueError):
            actions.installer_command("format-disk")

    def test_check_command_runs_the_scanner(self):
        from backend import cli
        self.assertEqual(cli.main(["check", SANDBOX]), 0)


class Docs(unittest.TestCase):
    def test_only_listed_guides_can_be_read(self):
        listed = docs.list_all()
        self.assertTrue(any(d["path"] == "after-a-scan/if-danger-found.md" for d in listed))
        self.assertIsNotNone(docs.read("after-a-scan/if-danger-found.md"))
        for bad in ("../README.md", "../../app/backend/server.py", "/etc/hosts", "after-a-scan/../../LICENSE"):
            self.assertIsNone(docs.read(bad), bad)


class Server(unittest.TestCase):
    """The HTTP layer: every security check from backend/server.py, exercised over a real socket."""

    @classmethod
    def setUpClass(cls):
        App.token = "test-key-" + "x" * 30
        App.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        App.port = App.httpd.server_address[1]
        threading.Thread(target=App.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        App.httpd.shutdown()

    def req(self, method, path, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", App.port, timeout=30)
        h = {"Host": f"127.0.0.1:{App.port}"}
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data, r

    def key(self, extra=None):
        h = {"X-Guard-Key": App.token}
        h.update(extra or {})
        return h

    def test_static_files_and_headers(self):
        status, body, r = self.req("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"<script type=\"module\"", body)
        self.assertIn("frame-ancestors 'none'", r.getheader("Content-Security-Policy"))
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(self.req("GET", "/js/main.js")[0], 200)

    def test_static_traversal_and_hidden_files_refused(self):
        for p in ("/../backend/server.py", "/js/../../backend/server.py", "/js/%2e%2e/%2e%2e/backend/cli.py", "/.hidden.js", "/js/x.py"):
            self.assertEqual(self.req("GET", p)[0], 404, p)

    def test_api_requires_the_key(self):
        self.assertEqual(self.req("GET", "/api/ping")[0], 403)
        self.assertEqual(self.req("GET", "/api/ping", {"X-Guard-Key": "wrong"})[0], 403)
        self.assertEqual(self.req("GET", "/api/ping", self.key())[0], 200)

    def test_dns_rebinding_and_cross_site_requests_refused(self):
        self.assertEqual(self.req("GET", "/api/ping", self.key({"Host": "evil.example:80"}))[0], 421)
        self.assertEqual(self.req("GET", "/api/ping", self.key({"Origin": "https://evil.example"}))[0], 403)
        self.assertEqual(self.req("POST", "/api/ping", self.key({"Content-Type": "application/x-www-form-urlencoded"}), "a=b")[0], 415)
        self.assertEqual(self.req("POST", "/api/ping", self.key({"Content-Type": "text/plain"}), "{}")[0], 415)
        self.assertEqual(self.req("OPTIONS", "/api/scan")[0], 405)

    def test_input_validation(self):
        j = self.key({"Content-Type": "application/json"})
        self.assertEqual(self.req("POST", "/api/reveal", j, json.dumps({"path": "/etc/hosts"}))[0], 400)
        self.assertEqual(self.req("POST", "/api/routine", j, json.dumps({"on": True, "time": "9:00; rm -rf ~"}))[0], 400)
        self.assertEqual(self.req("POST", "/api/settings", j, json.dumps({"github_user": "a/b"}))[0], 400)
        self.assertEqual(self.req("POST", "/api/protect", j, json.dumps({"action": "format-disk"}))[0], 400)
        self.assertEqual(self.req("POST", "/api/dismiss", j, json.dumps({"key": "../../x"}))[0], 400)
        self.assertEqual(self.req("POST", "/api/scan", j, json.dumps({"folders": ["/not/a/folder"]}))[0], 400)
        self.assertEqual(self.req("POST", "/api/ping", j, "x" * 70000)[0], 413)
        self.assertEqual(self.req("POST", "/api/ping", j, "[1,2]")[0], 400)
        self.assertEqual(self.req("GET", "/api/doc?path=../README.md", self.key())[0], 404)

    def test_state(self):
        status, body, _ = self.req("GET", "/api/state", self.key())
        self.assertEqual(status, 200)
        d = json.loads(body)
        self.assertEqual(d["app"], config.APP_NAME)
        self.assertIn("routine", d["protection"])
        self.assertEqual(d["settings"]["default_folders"], config.DEFAULT_FOLDERS)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        shutil.rmtree(SANDBOX, ignore_errors=True)
