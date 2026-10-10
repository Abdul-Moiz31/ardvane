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

import subprocess

from . import actions, launcher
from .config import APP_NAME, IDLE_LIMIT, INSTALLED, INSTANCE, KIT, VERSION
from .server import App, Handler
from .system import python_exe, read_json, write_private

PROG = "ardvane" if INSTALLED else "python3 app/dashboard.py"
USAGE = f"""{APP_NAME} {VERSION}: protection against malware that spreads through code. Runs only on this computer.

  {PROG}                             open the dashboard (add --no-browser to print its address instead)
  {PROG} scan [--quick] [FOLDER ...]  read-only scan of this computer and your projects
  {PROG} check [FOLDER]               scan one folder before you open it: a download, a coding test, a colleague's repo
  {PROG} protect [--dry-run]          turn on protection: git hooks, safe clone, npm and editor hardening
  {PROG} unprotect                    remove protection and restore your previous settings
  {PROG} fixes [list | history | fix ID | undo ID]
                                       fixes Ardvane can make for you, with undo
  {PROG} launcher [--remove]          add (or remove) the app icon
  {PROG} --version

The dashboard runs on 127.0.0.1 and closes itself about 20 minutes after you stop using it.
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
        print(f"{APP_NAME} is already open.", flush=True)
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
    print(f"{APP_NAME} is running on this computer only (port {App.port}).", flush=True)
    print("It closes itself about 20 minutes after you stop using it, or press Ctrl+C.", flush=True)
    if open_browser:
        webbrowser.open(url)
    else:
        print("Open this address — it contains your private key, don't share it:", url, flush=True)
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


def _call(cmd):
    """Run one of the kit's own scripts in this terminal and return its exit code."""
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        return 130
    except OSError as e:
        print(f"{APP_NAME}: could not start {cmd[0]}: {e}", file=sys.stderr)
        return 3


def _scanner(name, args):
    return _call([python_exe(), os.path.join(KIT, "scanner", name), *args])


# `ardvane <command> ...`: each command runs the same reviewed script the dashboard uses
COMMANDS = {
    "scan": lambda a: _call(actions.scan_command("--quick" in a, [x for x in a if x != "--quick"])),
    "check": lambda a: _scanner("checkrepo.py", a),
    "protect": lambda a: _call(actions.installer_command("install", "--dry-run" in a)),
    "unprotect": lambda a: _call(actions.installer_command("uninstall")),
    "fixes": lambda a: _scanner("autofix.py", a or ["list"]),
    "launcher": lambda a: print((launcher.remove() if "--remove" in a else launcher.install())[1]) or 0,
}


def main(argv):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    if argv[:1] in (["-h"], ["--help"], ["help"]):
        print(USAGE)
        return 0
    if argv[:1] in (["--version"], ["version"]):
        print(APP_NAME, VERSION)
        return 0
    if argv and argv[0] in COMMANDS:
        return COMMANDS[argv[0]](argv[1:])
    unknown = [a for a in argv if a != "--no-browser"]
    if unknown:
        print(f"unknown command: {unknown[0]}\n\n{USAGE}", file=sys.stderr)
        return 3
    return serve(open_browser="--no-browser" not in argv)
