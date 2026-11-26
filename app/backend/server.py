"""The local HTTP server: static files for the UI plus a small JSON API.

Security model
  * Listens on 127.0.0.1 only, on a random port.
  * Every API call must carry the random per-session key (header X-Guard-Key). The key is handed to the browser in
    the URL fragment, which browsers never send to a server, and is kept only in that tab.
  * The Host header must be 127.0.0.1:<port> (stops DNS-rebinding), a cross-site Origin is refused, and POSTs must be
    application/json (a plain cross-site form can't send that without a CORS preflight, which we never approve).
  * Strict Content-Security-Policy: only the dashboard's own scripts and styles can run.
  * Paths the API accepts are validated against what the app itself listed (reports, guides, scan findings).
"""
import hmac
import http.server
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.parse

from . import actions, detections, docs, fixes, historyjob, kit, launcher, reports, settings, status, tasks, tools, updates
from .config import APP_ID, APP_NAME, DEFAULT_FOLDERS, DEST, HOME, IS_MAC, KIT, OS_NAME, ROUTINE_LABEL, UI, VERSION
from .system import kit_env, python_exe, run
from .scanjob import ScanJob

STATIC_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
                ".png": "image/png", ".ico": "image/x-icon", ".svg": "image/svg+xml", ".woff2": "font/woff2"}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
TIME_RE = re.compile(r"(?:[01]\d|2[0-3]):[0-5]\d")


class App:
    """Process-wide state for one dashboard session."""
    token = ""
    port = 0
    job = None
    hjob = None                 # history scan / cleanup (historyjob.HistoryJob)
    rjob = None                 # report for a repository's owner (tools.ReportJob)
    busy = 0
    last_seen = time.time()
    lock = threading.Lock()
    httpd = None

    @classmethod
    def scan_state(cls, dismissed=()):
        return cls.job.state(dismissed) if cls.job else None


MAX_BODY = 64 * 1024                 # API requests are small JSON documents
MAX_DRAIN = 1024 * 1024


class ApiError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------------------------- API handlers
def current_findings():
    """Findings from this session's finished scan plus the newest saved reports."""
    found = tasks.findings_from_reports()
    job = App.job
    if job and job.finished and not job.cancelled:
        for sec in job.state()["sections"]:
            found += [tasks.finding(i["level"], i["text"], i["path"], job.finished, "scan") for i in sec["items"]]
    return found


def task_list(protection=None):
    data = tasks.sync(current_findings(), protection or status.protection(), set(settings.load()["dismissed"]),
                      checked=tasks.latest_checks())
    return tasks.overview(data)


def get_state(q):
    s = settings.load()
    folders, custom = settings.load_folders()
    protection = status.protection()
    return {"app": APP_NAME, "version": VERSION, "os": OS_NAME, "kit": KIT, "home": HOME,
            "protection": protection, "last_daily": reports.latest_daily(), "todo": task_list(protection)["counts"],
            "blocked_folders": reports.blocked_folders(), "update": updates.status_now(),
            "daily_app": dict(zip(("via", "ready"), daily_via_app())) if IS_MAC else None,
            "settings": {"autofix": s["autofix"], "github_enabled": s["github_enabled"], "github_user": s["github_user"],
                         "github_repos": s["github_repos"], "github_scope": s["github_scope"], "feed_updates": s["feed_updates"],
                         "package_lookups": s["package_lookups"], "update_checks": s["update_checks"], "folders": folders,
                         "folder_info": settings.folder_info(folders),
                         "folders_custom": custom, "default_folders": DEFAULT_FOLDERS, "gh": bool(shutil.which("gh"))},
            "feed": detections.status(), "scan": App.scan_state(s["dismissed"])}


def get_scan(q):
    return {"scan": App.scan_state(settings.load()["dismissed"])}


def get_reports(q):
    return {"reports": reports.list_all()}


def get_report(q):
    text = reports.read(q.get("id", ""))
    if text is None:
        raise ApiError(404, "report not found")
    return {"text": text}


def get_tasks(q):
    return task_list()


def get_docs(q):
    return {"docs": docs.list_all()}


def get_doc(q):
    text = docs.read(q.get("path", ""))
    if text is None:
        raise ApiError(404, "guide not found")
    return {"path": q["path"], "text": text}


def get_preview(q):
    code, out = actions.installer("install", dry_run=True)
    return {"code": code, "output": out}


def post_scan(b):
    if App.job and App.job.finished is None:
        raise ApiError(409, "a scan is already running")
    asked = [str(f) for f in b.get("folders") or []]
    folders = [p for p in (os.path.abspath(os.path.expanduser(f)) for f in asked) if os.path.isdir(p)]
    if asked and not folders:      # folders that are gone for now (an unplugged drive) are skipped, not fatal
        raise ApiError(400, "none of these folders exist: " + ", ".join(asked[:3]))
    user, repos, owned_only = "", [], False
    if b.get("github"):
        s = settings.load()
        user, repos, owned_only = s["github_user"], s["github_repos"], s["github_scope"] == "owned"
        if not user and not repos:
            raise ApiError(400, "add your GitHub username or a repository in Settings first")
    App.job = ScanJob("quick" if b.get("mode") == "quick" else "full", folders, user, repos, on_finish=_after_scan,
                      update_feed=settings.load()["feed_updates"], owned_only=owned_only)
    return {"scan": App.job.state()}


def _after_scan(job):
    """Automatic mode: apply the auto-safe fixes as soon as a scan finishes."""
    try:
        done = fixes.apply_auto_if_enabled(infected_projects())
        if any(e.get("ok") and e.get("kind") in ("quarantine", "process", "clean-file") for e in done):
            tasks.start_incident()
        return done
    except Exception as e:      # a failed fix must never lose the scan results
        return [{"title": "Automatic fixes", "ok": False, "error": str(e)}]


def infected_projects():
    """Project folders the last scan flagged as DANGER (the only folders a project fix may be offered for)."""
    job = App.job
    if not job or not job.finished:
        return []
    return sorted({i["path"] for s in job.state()["sections"] for i in s["items"]
                   if i["level"] == "danger" and i["path"] and os.path.isdir(i["path"]) and s["title"].startswith("Your projects")})


def get_fixes(q):
    return fixes.overview(infected_projects())


def post_fix(b):
    if fixes.mode() == "off":
        raise ApiError(400, "fixes are turned off in Settings")
    try:
        entry = fixes.apply(str(b.get("id", "")), infected_projects())
    except LookupError as e:
        raise ApiError(409, str(e))
    if entry.get("ok") and entry.get("target"):
        tasks.resolve_path(entry["target"])            # the matching to-do is done; the next scan double-checks it
    if entry.get("ok") and entry.get("kind") in ("quarantine", "process"):
        tasks.start_incident()                         # the computer was infected: recovery steps are still needed
    status.invalidate()
    return {"entry": entry, "fixes": fixes.overview(infected_projects())}


def post_unfix(b):
    try:
        entry = fixes.undo(str(b.get("id", "")))
    except (LookupError, ValueError, OSError) as e:
        raise ApiError(409, str(e))
    status.invalidate()
    return {"entry": entry, "fixes": fixes.overview(infected_projects())}


def post_cancel(b):
    if App.job:
        App.job.cancel()
    return {"ok": True}


def post_reveal(b):
    path = str(b.get("path", ""))
    if not App.job or path not in App.job.reported_paths() or not os.path.exists(path):   # only paths a scan reported
        raise ApiError(400, "not a file from the last scan")
    code, out = actions.reveal(path)
    return {"ok": code == 0, "output": out}


def post_dismiss(b):
    key = str(b.get("key", ""))
    if not re.fullmatch(r"[0-9a-f]{16}", key):
        raise ApiError(400, "bad key")
    with settings.editing() as s:
        settings.set_dismissed(s, key, not b.get("undo"))
    return {"ok": True}


def post_task(b):
    tid = str(b.get("id", ""))
    try:
        if "step" in b:
            tasks.set_step(tid, int(b["step"]), bool(b.get("done")))
        else:
            resolution = "mine" if b.get("resolution") == "mine" else "fixed"
            view = next((t for t in task_list()["tasks"] if t["id"] == tid), None)
            if view is None:
                raise KeyError(tid)
            if resolution == "mine":             # "it's mine" is only for warnings, and also hides them in results
                if view["group"] != "finding" or view["level"] != "warn":
                    raise ApiError(400, "only warnings can be marked as yours")
                with settings.editing() as s:
                    settings.set_dismissed(s, tid[2:], True)
            tasks.set_done(tid, bool(b.get("done", True)), resolution)
    except (KeyError, ValueError, TypeError):
        raise ApiError(404, "task not found")
    return task_list()


def post_feed_update(b):
    return detections.update()


def post_pick_folder(b):
    return actions.pick_folder()


def post_settings(b):
    """Lists ("github_repos", "folders") take a whole list, {"add": item} or {"remove": item}."""
    try:
        with settings.editing() as s:
            if "github_user" in b:
                s["github_user"] = settings.clean_github_user(b["github_user"])
            if "github_repos" in b:
                s["github_repos"] = settings.change_list(s["github_repos"], b["github_repos"], settings.clean_github_repos)
            if "github_enabled" in b:
                s["github_enabled"] = bool(b["github_enabled"]) and bool(s["github_user"])
            if "github_scope" in b:
                if b["github_scope"] not in ("all", "owned"):
                    raise ValueError("unknown GitHub scope")
                s["github_scope"] = b["github_scope"]
            for key in ("feed_updates", "package_lookups", "update_checks"):     # on/off switches
                if key in b:
                    s[key] = bool(b[key])
            if "autofix" in b:
                if b["autofix"] not in settings.AUTOFIX_MODES:
                    raise ValueError("unknown fix mode")
                s["autofix"] = b["autofix"]
            if "folders" in b:
                settings.change_folders(b["folders"])
    except ValueError as e:
        raise ApiError(400, str(e))
    return {"ok": True}


def _long_action(fn):
    """Run one system-changing action at a time."""
    with App.lock:
        if App.busy:
            raise ApiError(409, "another change is still running")
        App.busy += 1
    try:
        code, out = fn()
        return {"ok": code == 0, "code": code, "output": out.strip()[-6000:]}
    finally:
        status.invalidate()
        with App.lock:
            App.busy -= 1


def post_protect(b):
    action = b.get("action")
    if action not in ("install", "uninstall"):
        raise ApiError(400, "bad action")

    def go():
        code, out = actions.installer(action)
        if action == "uninstall" and code == 0:
            actions.set_routine(False)
        return code, out
    return _long_action(go)


def post_routine(b):
    on, at = bool(b.get("on")), str(b.get("time") or "09:00")
    if on and not TIME_RE.fullmatch(at):
        raise ApiError(400, "use a time like 09:00")
    return _long_action(lambda: actions.set_routine(on, at))


def post_launcher(b):
    def go():
        code, out = launcher.install() if b.get("action") == "install" else launcher.remove()
        r = status.routine()
        if code == 0 and r.get("on") and r.get("time"):         # the daily check now starts through the app (or not)
            actions.set_routine(True, r["time"])
        return code, out
    return _long_action(go)


def daily_via_app():
    """(the scheduled daily check starts through the Ardvane app, the app can do that)."""
    plist = os.path.join(HOME, "Library", "LaunchAgents", ROUTINE_LABEL + ".plist")
    ready = os.path.isfile(os.path.join(launcher.daily_helper_path(), "Contents", "MacOS", "applet"))
    try:
        with open(plist, encoding="utf-8") as f:
            via = launcher.DAILY_HELPER in f.read()
    except OSError:
        via = False
    return via, ready


def post_daily_now(b):
    """Run the daily check now - through the app when it can, so macOS asks for folder access while you're here."""
    via, ready = daily_via_app()
    if ready:
        code, out = run(["/usr/bin/open", "-g", "-a", launcher.daily_helper_path()], timeout=30)
        if code != 0:
            raise ApiError(500, out.strip()[-200:] or "couldn't start the daily check")
        return {"ok": True, "via": "app"}
    subprocess.Popen(["/bin/bash", os.path.join(DEST, "daily-check.sh")], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)
    return {"ok": True, "via": "script"}


def get_history(q):
    return {"job": App.hjob.state() if App.hjob else None}


def post_history(b):
    """Start a history scan, prepare a clean history, or push one. A push needs the repository name typed again."""
    action = str(b.get("action", ""))
    if App.hjob and App.hjob.finished is None:
        raise ApiError(409, "a history job is still running")
    try:
        target = historyjob.check_target(action, b.get("target"))
    except ValueError as e:
        raise ApiError(400, str(e))
    if action == "push":
        with open(os.path.join(target, "plan.json"), encoding="utf-8") as f:
            plan = json.load(f)
        if str(b.get("confirm", "")).strip() != plan.get("target"):
            raise ApiError(400, "type the repository name to confirm the push")
    App.hjob = historyjob.HistoryJob(action, target)
    return {"job": App.hjob.state()}


def post_history_cancel(b):
    if App.hjob:
        App.hjob.cancel()
    return {"ok": True}


def _gh_login():
    """The GitHub login the GitHub CLI is signed in as, or '' (not installed, not signed in, or only a CI token)."""
    gc = kit.module("github_check")
    login = gc.gh_login()
    return "" if not login or login == gc.CI_LOGIN else login


def get_github_login(q):
    """Is there a signed-in GitHub CLI Ardvane can use, and as whom (so Overview can offer one-click setup)."""
    s = settings.load()
    return {"gh": bool(shutil.which("gh")), "login": _gh_login(), "enabled": s["github_enabled"] and bool(s["github_user"])}


def post_github_enable(b):
    """Turn the GitHub check on for the account the GitHub CLI is signed in as."""
    login = _gh_login()
    if not login:
        raise ApiError(400, "the GitHub CLI isn't signed in: run `gh auth login` in a terminal first")
    with settings.editing() as s:
        s["github_user"], s["github_enabled"] = settings.clean_github_user(login), True
    return {"ok": True, "login": login}


def get_github_repos(q):
    """The repositories the GitHub login can see, to choose from in Settings (read-only, through github_check)."""
    cmd = [python_exe(), os.path.join(KIT, "scanner", "github_check.py")]
    user = settings.load()["github_user"]
    code, out = run(cmd + ([user] if user else []) + ["--list", "--json"], timeout=120, env=kit_env())
    try:
        data = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
    except ValueError:
        data = {}
    if "repos" not in data:
        raise ApiError(502, data.get("error") or "could not list your GitHub repositories")
    return {"repos": data["repos"][:1000]}


def _protect_module():
    return kit.module("github_protect")


def get_github_branches(q):
    """Repositories the last GitHub audit found open to force pushes, and the ones Ardvane has protected since."""
    gp = _protect_module()
    cache = kit.module("github_check").read_json(kit.module("github_check").AUDIT_FILE, {})
    return {"gh": bool(_gh_login()), "audited": cache.get("time"), "exposed": gp.exposed(),
            "protected": [dict(repo=k, **v) for k, v in gp.protected().items()]}


def post_github_branches(b):
    """Block force pushes on repositories the audit listed (or take Ardvane's ruleset off). Only listed repositories are accepted."""
    gp = _protect_module()
    action = b.get("action")
    if action not in ("protect", "undo"):
        raise ApiError(400, "bad action")
    allowed = {r["repo"].lower(): r["repo"] for r in (gp.exposed() if action == "protect" else [{"repo": k} for k in gp.protected()])}
    asked = [r["repo"] for r in gp.exposed()] if b.get("all") and action == "protect" else [str(r) for r in b.get("repos") or []]
    chosen = [allowed[r.lower()] for r in asked if r.lower() in allowed]
    if not chosen:
        raise ApiError(400, "none of these repositories is in the list from the last GitHub check")
    if not _gh_login():
        raise ApiError(400, "the GitHub CLI isn't signed in: run `gh auth login` in a terminal first")
    with App.lock:
        if App.busy:
            raise ApiError(409, "another change is still running")
        App.busy += 1
    try:
        results = gp.run(action, chosen)
    except (RuntimeError, ValueError) as e:
        raise ApiError(400, str(e))
    finally:
        with App.lock:
            App.busy -= 1
    return {"results": results, **get_github_branches({})}


def get_github_report(q):
    return {"job": App.rjob.state() if App.rjob else None}


def post_github_report(b):
    """Scan one repository and write the report for its owner (nothing is sent anywhere)."""
    if App.rjob and App.rjob.finished is None:
        raise ApiError(409, "a report is still being prepared")
    try:
        repo = kit.module("github_check").parse_repo(b.get("repo", ""))
    except ValueError as e:
        raise ApiError(400, str(e))
    App.rjob = tools.ReportJob(repo)
    return {"job": App.rjob.state()}


def post_github_issue(b):
    """Open the prepared report as an issue. Needs the repository name typed again: an issue on a public repository is public."""
    job = App.rjob
    if not job or not job.result or job.result["clean"]:
        raise ApiError(409, "prepare a report first")
    if str(b.get("confirm", "")).strip().lower() != job.result["repo"].lower():
        raise ApiError(400, "type the repository name to confirm")
    if not _gh_login():
        raise ApiError(400, "the GitHub CLI isn't signed in: run `gh auth login` in a terminal first")
    try:
        url = kit.module("report_owner").open_issue(job.result["repo"], job.result["report"])
    except RuntimeError as e:
        raise ApiError(502, str(e))
    return {"ok": True, "url": url}


def get_sandbox(q):
    exe, ready, message = tools.sandbox_runtime()
    return {"runtime": exe, "ready": ready, "message": message, "os": OS_NAME}


def post_sandbox(b):
    """Open a repository or folder in the sandbox, in a terminal window (it needs a real terminal for its shell)."""
    try:
        kind, spec, argv = tools.sandbox_command(str(b.get("target", "")))
    except ValueError as e:
        raise ApiError(400, str(e))
    shown = " ".join(argv[-3:] if argv[0] != "ardvane" else argv)
    if not tools.open_in_terminal(argv):
        return {"launched": False, "command": shown}
    return {"launched": True, "command": shown, "kind": kind}


def get_secrets(q):
    return kit.module("credaudit").audit()


def get_update(q):
    return {"update": updates.status_now()}


def post_update_check(b):
    updates.check()
    return {"update": updates.status_now()}


def post_update_apply(b):
    """Install the new version, refresh protection from it, then restart on it (same port and key: the tab reloads)."""
    if not updates.status_now()["available"]:
        raise ApiError(409, "Ardvane is already up to date")
    result = _long_action(updates.apply)
    if result["ok"]:
        updates.restart(App.port, App.token, App.httpd.shutdown)
        result["restarting"] = True
    return result


def post_quit(b):
    threading.Thread(target=App.httpd.shutdown, daemon=True).start()
    return {"ok": True}


GET_ROUTES = {"/api/ping": lambda q: {"ok": True}, "/api/state": get_state, "/api/scan": get_scan, "/api/reports": get_reports,
              "/api/report": get_report, "/api/tasks": get_tasks, "/api/fixes": get_fixes, "/api/docs": get_docs, "/api/doc": get_doc, "/api/preview-install": get_preview, "/api/update": get_update, "/api/history": get_history,
              "/api/github/repos": get_github_repos, "/api/github/login": get_github_login,
              "/api/github/branches": get_github_branches, "/api/github/report": get_github_report, "/api/sandbox": get_sandbox,
              "/api/secrets": get_secrets}
POST_ROUTES = {"/api/ping": lambda b: {"ok": True}, "/api/scan": post_scan, "/api/scan/cancel": post_cancel,
               "/api/reveal": post_reveal, "/api/dismiss": post_dismiss, "/api/task": post_task, "/api/fix": post_fix, "/api/fix/undo": post_unfix, "/api/pick-folder": post_pick_folder, "/api/feed/update": post_feed_update, "/api/settings": post_settings,
               "/api/protect": post_protect, "/api/routine": post_routine, "/api/launcher": post_launcher, "/api/quit": post_quit,
               "/api/update/check": post_update_check, "/api/update/apply": post_update_apply,
               "/api/history": post_history, "/api/history/cancel": post_history_cancel, "/api/daily/run-now": post_daily_now, "/api/github/enable": post_github_enable,
               "/api/github/branches": post_github_branches, "/api/github/report": post_github_report,
               "/api/github/issue": post_github_issue, "/api/sandbox": post_sandbox}


# ---------------------------------------------------------------------------------------------- HTTP plumbing
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = APP_ID
    sys_version = ""

    def log_message(self, *args):       # keep the terminal quiet
        pass

    def _host_ok(self):
        return self.headers.get("Host", "") in (f"127.0.0.1:{App.port}", f"localhost:{App.port}")

    def _origin_ok(self):
        origin = self.headers.get("Origin")
        return origin is None or origin in (f"http://127.0.0.1:{App.port}", f"http://localhost:{App.port}")

    def _key_ok(self):
        return bool(App.token) and hmac.compare_digest(self.headers.get("X-Guard-Key", ""), App.token)

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = json.dumps(body).encode() if isinstance(body, (dict, list)) else body
        self.send_response(code)
        for k, v in (("Content-Type", ctype), ("Content-Length", str(len(data))), ("Cache-Control", "no-store"),
                     ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer"),
                     ("Cross-Origin-Opener-Policy", "same-origin"), ("Cross-Origin-Resource-Policy", "same-origin"),
                     ("Content-Security-Policy", CSP)):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _error(self, code, message):
        self._send(code, {"error": message})

    def _static(self, path):
        rel = "index.html" if path == "/" else path.lstrip("/")
        parts = rel.split("/")
        ext = os.path.splitext(rel)[1]
        if ext not in STATIC_TYPES or any(p in ("", ".", "..") or p.startswith(".") for p in parts):
            return self._error(404, "not found")
        full = os.path.join(UI, *parts)
        if not os.path.realpath(full).startswith(os.path.realpath(UI) + os.sep):
            return self._error(404, "not found")
        try:
            with open(full, "rb") as f:
                return self._send(200, f.read(), STATIC_TYPES[ext])
        except OSError:
            return self._error(404, "not found")

    def _dispatch(self, routes, path, arg):
        fn = routes.get(path)
        if fn is None:
            return self._error(404, "not found")
        App.last_seen = time.time()
        try:
            return self._send(200, fn(arg))
        except ApiError as e:
            return self._error(e.code, str(e))
        except Exception as e:          # never send a traceback; a short message is enough
            return self._error(500, f"{e.__class__.__name__}: {e}"[:300])

    def do_GET(self):
        if not self._host_ok():
            return self._error(421, "wrong host")
        url = urllib.parse.urlsplit(self.path)
        if not url.path.startswith("/api/"):
            return self._static(url.path)
        if not (self._origin_ok() and self._key_ok()):
            return self._error(403, "forbidden")
        return self._dispatch(GET_ROUTES, url.path, dict(urllib.parse.parse_qsl(url.query)))

    def do_POST(self):
        if not self._host_ok():
            return self._error(421, "wrong host")
        if not (self._origin_ok() and self._key_ok()):
            return self._error(403, "forbidden")
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            return self._error(415, "JSON body required")
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            # Read (and drop) a moderately oversized body first: closing a socket with unread data sends a reset that
            # can reach the browser before this answer does. Anything bigger is refused without reading it.
            if length <= MAX_DRAIN:
                while length > 0:
                    chunk = self.rfile.read(min(length, 65536))
                    if not chunk:
                        break
                    length -= len(chunk)
            self.close_connection = True
            return self._error(413, "request too large")
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except ValueError:
            return self._error(400, "invalid JSON")
        if not isinstance(body, dict):
            return self._error(400, "invalid JSON")
        return self._dispatch(POST_ROUTES, urllib.parse.urlsplit(self.path).path, body)

    def _not_allowed(self):
        self._error(405, "method not allowed")

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = _not_allowed
