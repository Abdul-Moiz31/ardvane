"""Start / reuse the dashboard, and the `launcher` sub-command."""
import http.server
import json
import os
import secrets
import signal
import sys
import threading
import time
import urllib.request
import webbrowser

from . import launcher
from .config import APP_NAME, IDLE_LIMIT, INSTANCE, VERSION
from .server import App, Handler
from .system import read_json, write_private

USAGE = f"""{APP_NAME} — local dashboard for polinrider-survival-kit

  python3 app/dashboard.py                  open the dashboard in your browser
  python3 app/dashboard.py --no-browser     print the address instead of opening it
  python3 app/dashboard.py launcher         add an app icon (Applications / Start menu / applications menu)
  python3 app/dashboard.py launcher --remove
  python3 app/dashboard.py --version

Everything runs on this computer (127.0.0.1). The dashboard stops by itself a few minutes after you close its tab.
"""


def running_instance():
    """Address of a dashboard that is already running (so a second click reuses it), or None."""
    info = read_json(INSTANCE, {})
    port, token = info.get("port"), info.get("token")
    if not isinstance(port, int) or not isinstance(token, str):
        return None
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/ping", headers={"X-Guard-Key": token})
        with urllib.request.urlopen(req, timeout=2) as r:
            return f"http://127.0.0.1:{port}/#k={token}" if r.status == 200 else None
    except Exception:
        return None


def _watchdog():
    while True:
        time.sleep(15)
        scanning = App.job is not None and App.job.finished is None
        if not scanning and not App.busy and time.time() - App.last_seen > IDLE_LIMIT:
            App.httpd.shutdown()
            return


def _stop_on_sigterm(signum, frame):
    """Stopped by the system or `kill`: shut down cleanly, exactly like Ctrl+C."""
    raise KeyboardInterrupt


def serve(open_browser=True, port=0):
    url = running_instance()
    if url:
        print(f"{APP_NAME} is already open.")
        if open_browser:
            webbrowser.open(url)
        return 0
    App.token = secrets.token_urlsafe(32)
    App.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    App.httpd.daemon_threads = True
    App.port = App.httpd.server_address[1]
    App.last_seen = time.time()
    write_private(INSTANCE, json.dumps({"port": App.port, "token": App.token, "pid": os.getpid()}))
    url = f"http://127.0.0.1:{App.port}/#k={App.token}"
    threading.Thread(target=_watchdog, daemon=True).start()
    signal.signal(signal.SIGTERM, _stop_on_sigterm)
    print(f"{APP_NAME} is running on this computer only (port {App.port}).")
    print("It stops by itself a few minutes after you close the browser tab, or press Ctrl+C.")
    if open_browser:
        webbrowser.open(url)
    else:
        print("Open this address — it contains your private key, don't share it:", url)
    try:
        App.httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        if App.job:
            App.job.cancel()
        if read_json(INSTANCE, {}).get("pid") == os.getpid():
            try:
                os.remove(INSTANCE)
            except OSError:
                pass
    return 0


def main(argv):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    if argv[:1] in (["-h"], ["--help"]):
        print(USAGE)
        return 0
    if argv[:1] == ["--version"]:
        print(APP_NAME, VERSION)
        return 0
    if argv[:1] == ["launcher"]:
        code, message = launcher.remove() if "--remove" in argv else launcher.install()
        print(message)
        return code
    unknown = [a for a in argv if a != "--no-browser"]
    if unknown:
        print(f"unknown option: {unknown[0]}\n\n{USAGE}", file=sys.stderr)
        return 3
    return serve(open_browser="--no-browser" not in argv)
