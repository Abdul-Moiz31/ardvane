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
import threading
import time
import urllib.parse

from . import actions, docs, launcher, reports, settings, status, tasks
from .config import APP_ID, APP_NAME, DEFAULT_FOLDERS, HOME, KIT, OS_NAME, UI, VERSION
from .scanjob import ScanJob

STATIC_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
                ".png": "image/png", ".ico": "image/x-icon", ".svg": "image/svg+xml"}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
TIME_RE = re.compile(r"(?:[01]\d|2[0-3]):[0-5]\d")


class App:
    """Process-wide state for one dashboard session."""
    token = ""
    port = 0
    job = None
    busy = 0
    last_seen = time.time()
    lock = threading.Lock()
    httpd = None

    @classmethod
    def scan_state(cls, dismissed=()):
        return cls.job.state(dismissed) if cls.job else None


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
            found += [tasks.finding(i["level"], i["text"], i["path"], job.finished) for i in sec["items"]]
    return found


def task_list(protection=None):
    data = tasks.sync(current_findings(), protection or status.protection(), set(settings.load()["dismissed"]))
    return tasks.overview(data)


def get_state(q):
    s = settings.load()
    folders, custom = settings.load_folders()
    protection = status.protection()
    return {"app": APP_NAME, "version": VERSION, "os": OS_NAME, "kit": KIT, "home": HOME,
            "protection": protection, "last_daily": reports.latest_daily(), "todo": task_list(protection)["counts"],
            "settings": {"github_enabled": s["github_enabled"], "github_user": s["github_user"], "folders": folders,
                         "folders_custom": custom, "default_folders": DEFAULT_FOLDERS, "gh": bool(shutil.which("gh"))},
            "scan": App.scan_state(s["dismissed"])}


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
    folders = []
    for f in b.get("folders") or []:
        p = os.path.abspath(os.path.expanduser(str(f)))
        if not os.path.isdir(p):
            raise ApiError(400, f"folder not found: {f}")
        folders.append(p)
    user = ""
    if b.get("github"):
        user = settings.load()["github_user"]
        if not user:
            raise ApiError(400, "add your GitHub username in Settings first")
    App.job = ScanJob("quick" if b.get("mode") == "quick" else "full", folders, user)
    return {"scan": App.job.state()}


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
    s = settings.load()
    settings.set_dismissed(s, key, not b.get("undo"))
    settings.save(s)
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
                s = settings.load()
                settings.set_dismissed(s, tid[2:], True)
                settings.save(s)
            tasks.set_done(tid, bool(b.get("done", True)), resolution)
    except (KeyError, ValueError, TypeError):
        raise ApiError(404, "task not found")
    return task_list()


def post_settings(b):
    s = settings.load()
    try:
        if "github_user" in b:
            s["github_user"] = settings.clean_github_user(b["github_user"])
        if "github_enabled" in b:
            s["github_enabled"] = bool(b["github_enabled"]) and bool(s["github_user"])
        if "folders" in b:
            if not isinstance(b["folders"], list):
                raise ValueError("folders must be a list")
            settings.save_folders(b["folders"])
    except ValueError as e:
        raise ApiError(400, str(e))
    settings.save(s)
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
    return _long_action(launcher.install if b.get("action") == "install" else launcher.remove)


def post_quit(b):
    threading.Thread(target=App.httpd.shutdown, daemon=True).start()
    return {"ok": True}


GET_ROUTES = {"/api/ping": lambda q: {"ok": True}, "/api/state": get_state, "/api/scan": get_scan, "/api/reports": get_reports,
              "/api/report": get_report, "/api/tasks": get_tasks, "/api/docs": get_docs, "/api/doc": get_doc, "/api/preview-install": get_preview}
POST_ROUTES = {"/api/ping": lambda b: {"ok": True}, "/api/scan": post_scan, "/api/scan/cancel": post_cancel,
               "/api/reveal": post_reveal, "/api/dismiss": post_dismiss, "/api/task": post_task, "/api/settings": post_settings,
               "/api/protect": post_protect, "/api/routine": post_routine, "/api/launcher": post_launcher, "/api/quit": post_quit}


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
        if length > 64 * 1024:
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
