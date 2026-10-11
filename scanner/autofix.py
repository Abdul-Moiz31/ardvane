#!/usr/bin/env python3
"""autofix — fix what the kit can fix safely, with undo. Part of Ardvane (MIT License).

Python 3.8+, standard library only.

Safety rules
  * Nothing is ever deleted. Malware is MOVED to ~/.checkrepo/quarantine (with a record of where it came from) and
    made non-executable, so it is kept as evidence and can be restored.
  * Every fix is recorded in ~/.checkrepo/fixes.json and can be undone (except stopping a process).
  * Fixes only act on targets this tool detects itself: a fixed list of known malware locations
    (lists/malware-paths.txt), exact malware file names, the editor/npm/git settings the kit manages, and project
    folders that checkrepo still flags as DANGER at the moment of the fix. A path is never taken from text inside a
    scanned file, a symlink is moved as a link (never followed), and protected folders (~/.ssh, keychains, the home
    folder itself, …) are refused.
  * Each fix is checked afterwards: the problem must no longer be detected.
  * "Automatic" only applies fixes marked auto-safe, and only when Settings → Automatic fixes is set to "Automatic".
    Stopping processes and moving projects or loose scripts always need a person to confirm.

Usage
  autofix.py list [--json]                 what can be fixed right now
  autofix.py fix ID [--project DIR] [--json]   apply one fix (as a person, from the dashboard or terminal)
  autofix.py auto [--json]                 apply every auto-safe fix (used by the daily check in Automatic mode)
  autofix.py undo HISTORY_ID [--json]      undo a fix
  autofix.py history [--json]
Exit code: 0 ok, 1 a fix failed, 3 usage error / refused.
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kitlib import DEST, HOME, IS_MAC, IS_WIN, find, load_checkrepo, read_json, safe_output, setting, write_json  # noqa: E402

QUARANTINE = os.path.join(DEST, "quarantine")
HISTORY = os.path.join(DEST, "fixes.json")
MODES = ("ask", "auto", "off")
DEFAULT_MODE = "ask"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Never moved, whatever a list or a scan says (compared after resolving the parent folder)
PROTECTED = [HOME, DEST, os.path.join(HOME, ".ssh"), os.path.join(HOME, ".gnupg"), os.path.join(HOME, ".aws"),
             os.path.join(HOME, ".config", "gh"), os.path.join(HOME, "Library", "Keychains"),
             os.path.join(HOME, "Library"), os.path.join(HOME, "Documents"), os.path.join(HOME, "Desktop"),
             os.path.join(HOME, "Downloads"), os.path.join(HOME, "AppData")]
# Exact file names that only the malware uses (searched 2 levels deep in these folders)
MALWARE_NAMES = {"SvcHostUpdate.py", "SvcHostUpdate.js", "MicrosoftCLROptimization.vbs", "MicrosoftSystem64.exe"}
NAME_ROOTS = ([os.environ.get(v, "") for v in ("TEMP", "APPDATA", "LOCALAPPDATA")] if IS_WIN else [])
PROCESS_RE = re.compile(r"MicrosoftSystem64|SvcHostUpdate|MicrosoftCLROptimization|tg14xq|node(?:\.exe)?\"?\s+\S*\.(?:eot|woff2?|ttf|otf|llf)(?:\s|$)", re.I)
# A command whose program is one of these only mentions a malware name (someone searching or reading), it isn't malware
TEXT_TOOLS = {"grep", "egrep", "rg", "ag", "ack", "less", "more", "cat", "head", "tail", "vi", "vim", "nvim", "nano", "emacs", "code", "find", "findstr", "select-string"}
EDITORS = ("Code", "Cursor", "Windsurf")
EDITOR_NAMES = {"Code": "VS Code", "Cursor": "Cursor", "Windsurf": "Windsurf"}


def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
        return r.returncode, (r.stdout or "").strip()
    except (OSError, subprocess.SubprocessError) as e:
        return -1, str(e)


def short(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def pretty(path):
    return "~" + path[len(HOME):] if path.startswith(HOME + os.sep) else path


def fix(fid, kind, title, detail, auto, target="", changes=(), undo=True):
    return {"id": fid, "kind": kind, "title": title, "detail": detail, "auto": auto, "target": target,
            "changes": list(changes), "undoable": undo}


# ---------------------------------------------------------------------------------------------- safety
def _inside(path, folder):
    path, folder = os.path.normcase(path), os.path.normcase(folder)
    return path == folder or path.startswith(folder.rstrip(os.sep) + os.sep)


def check_movable(path):
    """Raise ValueError unless `path` may be moved to quarantine. Symlinks are judged (and moved) as links."""
    p = os.path.abspath(path)
    if not os.path.lexists(p):
        raise ValueError(f"{pretty(p)} no longer exists")
    resolved = os.path.join(os.path.realpath(os.path.dirname(p)), os.path.basename(p))
    if not os.path.islink(p):
        resolved = os.path.realpath(p)
    for candidate in {p, resolved}:
        for protected in PROTECTED:
            if os.path.normcase(candidate) == os.path.normcase(os.path.realpath(protected)) or os.path.normcase(candidate) == os.path.normcase(protected):
                raise ValueError(f"refusing to move a protected folder: {pretty(candidate)}")
        for secret in (".ssh", ".gnupg", ".aws", "Keychains"):
            for base in (HOME, os.path.realpath(HOME)):
                if _inside(candidate, os.path.join(base, secret)) or _inside(candidate, os.path.join(base, "Library", secret)):
                    raise ValueError(f"refusing to touch {pretty(candidate)}")
    allowed = [HOME, os.path.realpath(HOME), tempfile.gettempdir(), os.path.realpath(tempfile.gettempdir()), "/tmp", "/private/tmp"]
    allowed += [os.environ.get(v, "") for v in ("LOCALAPPDATA", "APPDATA", "TEMP") if os.environ.get(v)]
    if not any(a and _inside(resolved, a) for a in allowed):
        raise ValueError(f"refusing to move something outside your home or temp folder: {pretty(resolved)}")
    if _inside(resolved, DEST) or _inside(resolved, os.path.realpath(DEST)):
        raise ValueError("refusing to move the kit's own files")


# ---------------------------------------------------------------------------------------------- detection
def known_paths():
    """(path, auto) for this system from lists/malware-paths.txt."""
    listing = find("lists", "malware-paths.txt")
    system = "windows" if IS_WIN else "mac" if IS_MAC else "linux"
    out = []
    try:
        with open(listing, encoding="utf-8") as f:
            for line in f:
                parts = line.split("#", 1)[0].split(None, 2)
                if len(parts) != 3:
                    continue
                scope, mode, path = parts
                if scope == "all" or scope == system or (scope == "unix" and not IS_WIN):
                    path = os.path.expandvars(os.path.expanduser(path.strip()))
                    if "%" not in path and "$" not in path:      # an unset variable must never become a relative path
                        out.append((os.path.normpath(path.replace("/", os.sep) if IS_WIN else path), mode == "auto"))
    except (OSError, TypeError):
        pass
    return out


def editor_settings():
    for name in EDITORS:
        if IS_WIN:
            folder = os.path.join(os.environ.get("APPDATA", ""), name, "User")
        elif IS_MAC:
            folder = os.path.join(HOME, "Library", "Application Support", name, "User")
        else:
            folder = os.path.join(HOME, ".config", name, "User")
        if os.path.isdir(folder):
            yield name, os.path.join(folder, "settings.json")


def _read_settings(path):
    """dict, or None when the file has comments / trailing commas (then it's left for the person to edit)."""
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        return {}
    except OSError:
        return None
    try:
        value = json.loads(text or "{}")
        return value if isinstance(value, dict) else None
    except ValueError:
        return None


EDITOR_FIX = {"task.allowAutomaticTasks": "off", "security.workspace.trust.enabled": True}


def detect_editors():
    out = []
    for name, path in editor_settings():
        d = _read_settings(path)
        if d is None:
            continue
        wrong = {k: v for k, v in EDITOR_FIX.items() if d.get(k) != v and not (k == "security.workspace.trust.enabled" and k not in d)}
        if wrong:
            out.append(fix("editor:" + name, "editor", f"Make {EDITOR_NAMES[name]} safe to open projects in",
                           "Any folder you open can run code automatically with the current settings.", True, path,
                           [f'set "{k}": {json.dumps(v)}' for k, v in wrong.items()] + ["the original file is backed up first"]))
    return out


def npm_path():
    return shutil.which("npm")


def detect_npm():
    npm = npm_path()
    if not npm:
        return []
    code, out = run([npm, "config", "get", "ignore-scripts"])
    if code != 0 or out.splitlines()[-1:] == ["true"]:
        return []
    return [fix("npm", "npm", "Block npm install scripts", "Packages can run code on your computer while they install.", True, "",
                ["npm config set ignore-scripts true"])]


def detect_hooks():
    hooks = os.path.join(DEST, "hooks")
    if not (os.path.isfile(os.path.join(DEST, "hooks-enabled")) and os.path.isfile(os.path.join(hooks, "dispatch"))):
        return []
    code, current = run(["git", "config", "--global", "--get", "core.hooksPath"])
    if os.path.normcase(os.path.normpath(current or "")) == os.path.normcase(os.path.normpath(hooks)):
        return []
    return [fix("git-hooks", "hooks", "Switch the git protection back on", "Something turned off the kit's git hooks, so clones and pushes aren't checked.",
                True, "", [f"git config --global core.hooksPath {hooks}"])]


def detect_paths():
    out = []
    for path, auto in known_paths():
        if os.path.lexists(path):
            out.append(fix("path:" + short(path), "quarantine", f"Quarantine {pretty(path)}", "A known location of this malware.", auto, path,
                           [f"move {pretty(path)} to ~/.checkrepo/quarantine (not deleted, can be restored)"]
                           + (["stop it from starting automatically"] if path.endswith((".plist", ".service", ".desktop")) else [])))
    for root in NAME_ROOTS:
        if not root or not os.path.isdir(root):
            continue
        base = root.rstrip(os.sep).count(os.sep)
        for dp, dns, fns in os.walk(root):
            if dp.count(os.sep) - base >= 2:
                dns[:] = []
            for fn in fns:
                if fn in MALWARE_NAMES:
                    p = os.path.join(dp, fn)
                    out.append(fix("path:" + short(p), "quarantine", f"Quarantine {p}", "A file name only this malware uses.", False, p,
                                   [f"move {p} to quarantine (not deleted, can be restored)"]))
    return out


def detect_scripts():
    """Loose scripts with malware markers in ~/Library/Application Support (how the dropper hid). Always asks."""
    if not IS_MAC:
        return []
    root = os.path.join(HOME, "Library", "Application Support")
    if not os.path.isdir(root):
        return []
    skip = re.compile(r"^(Code|Cursor|Windsurf|Claude|Google|Slack|Notion|Microsoft|Docker|Linear|Figma|Discord|BraveSoftware|Arc|Chromium|Firefox|Electron|JetBrains)$")
    cr, out = load_checkrepo(), []
    for entry in os.scandir(root):
        if skip.match(entry.name):
            continue
        candidates = [entry] if entry.is_file(follow_symlinks=False) else []
        if entry.is_dir(follow_symlinks=False):
            try:
                candidates = [e for e in os.scandir(entry.path) if e.is_file(follow_symlinks=False)]
            except OSError:
                continue
        for e in candidates:
            if not e.name.endswith((".js", ".cjs", ".mjs")):
                continue
            try:
                if e.stat(follow_symlinks=False).st_size < 10_000:
                    continue
                with open(e.path, encoding="utf-8", errors="replace") as f:
                    text = f.read(5_000_000)
            except OSError:
                continue
            if cr.marker_hits(text) or cr.looks_obfuscated(text):
                out.append(fix("path:" + short(e.path), "quarantine", f"Quarantine {pretty(e.path)}",
                               "A script with this malware's code, hidden among app files.", False, e.path,
                               [f"move {pretty(e.path)} to quarantine (not deleted, can be restored)"]))
    return out


def list_processes():
    """[(pid, command line)] of every process."""
    if IS_WIN:
        code, out = run(["powershell", "-NoProfile", "-Command",
                         "Get-CimInstance Win32_Process | ForEach-Object { \"$($_.ProcessId)`t$($_.Name) $($_.CommandLine)\" }"], timeout=60)
        rows = [l.split("\t", 1) for l in out.splitlines() if "\t" in l]
    else:
        code, out = run(["ps", "-axo", "pid=,args="])
        rows = [l.strip().split(None, 1) for l in out.splitlines() if l.strip()]
    return [(int(r[0]), r[1] if len(r) > 1 else "") for r in rows if r and r[0].strip().isdigit()]


def detect_processes(processes=None):
    me = {os.getpid(), os.getppid()}
    out = []
    for pid, cmd in (processes if processes is not None else list_processes()):
        program = os.path.basename((cmd.split() or [""])[0]).lower().replace(".exe", "")
        if pid in me or pid <= 1 or "autofix" in cmd or program in TEXT_TOOLS or not PROCESS_RE.search(cmd):
            continue
        out.append(fix(f"process:{pid}:{short(cmd)}", "process", f"Stop malware process {pid}", cmd[:160], False, str(pid),
                       [f"stop process {pid}: {cmd[:120]}"], undo=False))
    return out


def detect_projects(folders):
    """Project folders that checkrepo flags as DANGER right now. Always asks."""
    if not folders:
        return []
    cr, out = load_checkrepo(), []
    for folder in folders:
        p = os.path.abspath(os.path.expanduser(folder))
        if not os.path.isdir(p):
            continue
        try:
            check_movable(p)
        except ValueError:
            continue
        s = cr.Scan(p)
        s.walk()
        if any(f[0] == "DANGER" for f in s.findings):
            out.append(fix("project:" + short(p), "quarantine", f"Move the infected project {pretty(p)} to quarantine",
                           "Use this for downloads and coding tests. For your own repository, clean it on GitHub instead.", False, p,
                           [f"move {pretty(p)} to ~/.checkrepo/quarantine (not deleted, can be restored)"]))
    return out


def detect(projects=()):
    found = detect_editors() + detect_npm() + detect_hooks() + detect_paths() + detect_scripts() + detect_processes() + detect_projects(projects)
    seen, out = set(), []
    for f in found:
        if f["id"] not in seen:
            seen.add(f["id"])
            out.append(f)
    return out


# ---------------------------------------------------------------------------------------------- applying
def _neutralise(path):
    """Make quarantined files non-executable. Returns the original modes so a restore can put them back."""
    modes = {}

    def one(p, is_dir):
        try:
            st = os.lstat(p)
            if os.path.islink(p):
                return
            modes[os.path.relpath(p, path) if p != path else "."] = st.st_mode & 0o7777
            os.chmod(p, 0o700 if is_dir else 0o600)
        except OSError:
            pass
    if os.path.isdir(path) and not os.path.islink(path):
        for dp, dns, fns in os.walk(path):
            one(dp, True)
            for fn in fns:
                one(os.path.join(dp, fn), False)
            if len(modes) > 20000:
                break
    else:
        one(path, False)
    return modes


def _stop_autostart(path):
    if IS_MAC and path.endswith(".plist"):
        run(["launchctl", "bootout", f"gui/{os.getuid()}", path])
    elif not IS_WIN and path.endswith(".service"):
        run(["systemctl", "--user", "disable", "--now", os.path.basename(path)])


def quarantine(path, reason):
    check_movable(path)
    _stop_autostart(path)
    folder = os.path.join(QUARANTINE, time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3))
    os.makedirs(folder, mode=0o700)
    sha = None
    if os.path.isfile(path) and not os.path.islink(path):
        with open(path, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
    target = os.path.join(folder, "item")
    shutil.move(path, target)
    modes = _neutralise(target)
    write_json(os.path.join(folder, "manifest.json"), {"original": path, "sha256": sha, "reason": reason,
                                                       "time": time.time(), "modes": modes})
    return {"folder": folder, "original": path, "modes": modes}


def _backup(path):
    folder = os.path.join(QUARANTINE, "settings-backups")
    os.makedirs(folder, mode=0o700, exist_ok=True)
    dest = os.path.join(folder, time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3) + "-" + os.path.basename(path))
    if os.path.exists(path):
        shutil.copy2(path, dest)
        return dest
    return None


def _apply(f, projects):
    kind = f["kind"]
    if kind == "editor":
        path = f["target"]
        d = _read_settings(path)
        if d is None:
            raise ValueError("the settings file has comments — edit it by hand")
        backup = _backup(path)
        d.update(EDITOR_FIX)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(d, indent=4, ensure_ascii=False) + "\n")
        return {"backup": backup, "path": path}
    if kind == "npm":
        npm = npm_path()
        _, before = run([npm, "config", "get", "ignore-scripts"])
        code, out = run([npm, "config", "set", "ignore-scripts", "true"])
        if code != 0:
            raise ValueError(out or "npm config failed")
        return {"before": (before.splitlines() or [""])[-1]}
    if kind == "hooks":
        _, before = run(["git", "config", "--global", "--get", "core.hooksPath"])
        code, out = run(["git", "config", "--global", "core.hooksPath", os.path.join(DEST, "hooks")])
        if code != 0:
            raise ValueError(out or "git config failed")
        return {"before": before}
    if kind == "quarantine":
        return quarantine(f["target"], f["title"])
    if kind == "process":
        pid = int(f["target"])
        if IS_WIN:
            code, out = run(["taskkill", "/PID", str(pid), "/F"])
            if code != 0:
                raise ValueError(out or "could not stop the process")
        else:
            os.kill(pid, signal.SIGTERM)
            for _ in range(20):
                time.sleep(0.1)
                try:
                    os.kill(pid, 0)
                except OSError:
                    break
            else:
                os.kill(pid, signal.SIGKILL)
        return {"pid": pid}
    raise ValueError("unknown fix")


def _history():
    return read_json(HISTORY, [])


def _record(entry):
    hist = _history()
    hist.append(entry)
    write_json(HISTORY, hist[-500:])


def apply(fix_id, how="manual", projects=()):
    """Apply one fix that is detected right now. how: 'manual' (a person confirmed) or 'auto'."""
    current = {f["id"]: f for f in detect(projects)}
    f = current.get(fix_id)
    if f is None:
        raise LookupError("nothing to fix — it's already fixed or no longer found")
    if how == "auto" and not f["auto"]:
        raise PermissionError("this fix always needs a person to confirm it")
    entry = {"id": secrets.token_hex(6), "fix": f["id"], "kind": f["kind"], "title": f["title"], "target": f["target"],
             "how": how, "time": time.time(), "ok": False, "verified": False, "undoable": f["undoable"], "undone_at": None}
    try:
        entry["undo"] = _apply(f, projects)
        entry["ok"] = True
        entry["verified"] = fix_id not in {x["id"] for x in detect(projects)}
    except (OSError, ValueError, shutil.Error) as e:
        entry["error"] = str(e)
    _record(entry)
    return entry


def apply_auto():
    """Every auto-safe fix, only when the user chose Automatic in Settings."""
    if setting("autofix", DEFAULT_MODE) != "auto":
        raise PermissionError("automatic fixes are not turned on (Settings → Automatic fixes)")
    return [apply(f["id"], "auto") for f in detect() if f["auto"]]


def undo(entry_id):
    hist = _history()
    entry = next((e for e in hist if e["id"] == entry_id), None)
    if entry is None or not entry.get("ok") or entry.get("undone_at") or not entry.get("undoable"):
        raise LookupError("this fix can't be undone")
    u, kind = entry.get("undo") or {}, entry["kind"]
    if kind == "quarantine":
        item = os.path.join(u["folder"], "item")
        if os.path.lexists(u["original"]):
            raise ValueError(f"{pretty(u['original'])} exists again — move it away first")
        os.makedirs(os.path.dirname(u["original"]), exist_ok=True)
        for rel, mode in (u.get("modes") or {}).items():
            try:
                os.chmod(item if rel == "." else os.path.join(item, rel), mode)
            except OSError:
                pass
        shutil.move(item, u["original"])
    elif kind == "editor":
        if u.get("backup"):
            shutil.copy2(u["backup"], u["path"])
        elif os.path.exists(u["path"]):
            os.remove(u["path"])                     # the file didn't exist before the fix
    elif kind == "npm":
        npm = npm_path()
        run([npm, "config", "set", "ignore-scripts", u["before"]] if u.get("before") in ("true", "false") else [npm, "config", "delete", "ignore-scripts"])
    elif kind == "hooks":
        run(["git", "config", "--global", "core.hooksPath", u["before"]] if u.get("before") else ["git", "config", "--global", "--unset", "core.hooksPath"])
    entry["undone_at"] = time.time()
    write_json(HISTORY, hist)
    return entry


def history():
    return list(reversed(_history()))


# ---------------------------------------------------------------------------------------------- command line
def _arg(argv, name):
    return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else None


def main(argv):
    safe_output()
    as_json = "--json" in argv
    args = [a for a in argv if a != "--json"]
    cmd = args[0] if args else ""
    say = (lambda v: print(json.dumps(v))) if as_json else None
    try:
        if cmd == "list":
            items = detect()
            if say:
                return say(items) or 0
            for f in items:
                print(f"{'auto' if f['auto'] else 'ask '}  {f['id']}  {f['title']}")
            return 0
        if cmd == "fix" and len(args) > 1:
            project = _arg(args, "--project")
            e = apply(args[1], "manual", [project] if project else [])
            if say:
                say(e)
            else:
                print(("🔧 " + e["title"] + (" — verified" if e["verified"] else "")) if e["ok"] else f"✘ {e['title']}: {e.get('error')}")
            return 0 if e["ok"] else 1
        if cmd == "auto":
            done = apply_auto()
            if say:
                return say(done) or 0
            for e in done:
                print(f"  🔧 fixed automatically: {e['title']}" + ("" if e["ok"] else f" — FAILED: {e.get('error')}") + ("  (undo in the dashboard)" if e["ok"] and e["undoable"] else ""))
            return 0 if all(e["ok"] for e in done) else 1
        if cmd == "undo" and len(args) > 1:
            e = undo(args[1])
            if say:
                say(e)
            else:
                print("↩ undone: " + e["title"])
            return 0
        if cmd == "history":
            items = history()
            if say:
                return say(items) or 0
            for e in items:
                print(f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(e['time']))}  {e['id']}  {e['how']:6}  {'undone' if e.get('undone_at') else 'ok' if e['ok'] else 'failed'}  {e['title']}")
            return 0
    except (LookupError, PermissionError, ValueError, OSError) as e:
        if as_json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"autofix: {e}", file=sys.stderr)
        return 3
    print(__doc__)
    return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
