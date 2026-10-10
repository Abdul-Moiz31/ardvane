#!/usr/bin/env python3
"""github_check — read-only check of a GitHub account for PolinRider-style activity.

Part of polinrider-survival-kit (MIT License). Python 3.8+, no dependencies.

What it does (never changes anything on GitHub):
  1. Lists the account's repositories and the ones pushed recently.
  2. Warns when many repositories were pushed within one hour (the worm force-pushes into every repo it can reach).
  3. Downloads the default branch of each recently pushed repository as an archive into a temporary folder,
     scans it with checkrepo, and deletes the temporary folder. Nothing from the archive is ever run.

Access:
  - If the GitHub CLI (`gh`) is installed and logged in, it is used, so private repositories are checked too.
    Your token stays inside `gh`; this script never reads or stores it.
  - Otherwise the public API is used (public repositories only, 60 requests per hour).

Usage:
  github_check.py USERNAME [--days N] [--max-repos N] [--json] [--rescan]

Repositories already scanned clean are skipped until they receive a new push (remembered in
~/.checkrepo/github-seen.json); --rescan scans them again.
Exit code: 0 clean, 1 danger found, 2 warnings only, 3 could not check.
"""
import datetime
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
API = "https://api.github.com"
MAX_ARCHIVE = 60 * 1024 * 1024
BURST_REPOS, BURST_WINDOW = 5, 3600
SEEN_FILE = os.path.expanduser("~/.checkrepo/github-seen.json")


def load_checkrepo():
    for p in (os.path.join(HERE, "checkrepo.py"), os.path.expanduser("~/.checkrepo/checkrepo.py")):
        if os.path.isfile(p):
            spec = importlib.util.spec_from_file_location("checkrepo", p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    raise SystemExit("github_check: checkrepo.py not found")


def gh_login():
    """The login `gh` is authenticated as, or None (not installed / not logged in)."""
    exe = shutil.which("gh")
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "api", "user", "--jq", ".login"], capture_output=True, text=True, timeout=20)
        return r.stdout.strip() or None if r.returncode == 0 else None
    except Exception:
        return None


class Client:
    def __init__(self, use_gh):
        self.use_gh = use_gh
        self.gh = shutil.which("gh") if use_gh else None

    def get(self, path, binary=False, limit=5 * 1024 * 1024):
        if self.gh:
            r = subprocess.run([self.gh, "api", "-H", "Accept: application/vnd.github+json", path],
                               capture_output=True, timeout=180)
            if r.returncode != 0:
                raise RuntimeError((r.stderr or b"").decode("utf-8", "replace").strip()[:200] or "gh api failed")
            data = r.stdout
        else:
            req = urllib.request.Request(API + path, headers={"Accept": "application/vnd.github+json",
                                                              "User-Agent": "polinrider-survival-kit"})
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = resp.read(limit + 1)
            except urllib.error.HTTPError as e:
                if e.code == 403 and e.headers.get("X-RateLimit-Remaining") == "0":
                    raise RuntimeError("GitHub's hourly limit for anonymous checks was reached - try again later, or log in with `gh auth login` to check private repositories too")
                if e.code == 404:
                    raise RuntimeError("not found")
                raise RuntimeError(f"GitHub returned HTTP {e.code}")
            except urllib.error.URLError as e:
                raise RuntimeError(f"no connection to GitHub ({e.reason})")
        if len(data) > limit:
            raise RuntimeError("response too large")
        return data if binary else json.loads(data.decode("utf-8"))


def parse_time(s):
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def safe_extract(blob, dest):
    """Extract regular files only; refuse absolute paths, '..', links and devices. Strips the top folder."""
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for m in tf.getmembers():
            parts = m.name.replace("\\", "/").split("/")[1:]       # drop "<owner>-<repo>-<sha>/"
            if not parts or not m.isfile() or m.name.startswith("/") or ".." in parts or m.size > 20 * 1024 * 1024:
                continue
            target = os.path.join(dest, *parts)
            if not os.path.realpath(target).startswith(os.path.realpath(dest) + os.sep):
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            with open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def bursts(times):
    """Largest number of repositories pushed within any one-hour window, with the window start."""
    times = sorted(times)
    best, start, j = 0, None, 0
    for i, t in enumerate(times):
        while (t - times[j]).total_seconds() > BURST_WINDOW:
            j += 1
        if i - j + 1 > best:
            best, start = i - j + 1, times[j]
    return best, start


def load_seen():
    try:
        with open(SEEN_FILE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_seen(seen):
    try:
        os.makedirs(os.path.dirname(SEEN_FILE), exist_ok=True)
        tmp = SEEN_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(seen, f)
        os.replace(tmp, SEEN_FILE)
    except OSError:
        pass


def check(user, days=7, max_repos=15, rescan=False):
    cr = load_checkrepo()
    login = gh_login()
    client = Client(use_gh=bool(login))
    result = {"user": user, "source": "gh" if login else "public", "repos": 0, "recent": [], "scanned": [],
              "findings": [], "notes": []}
    if login and login.lower() == user.lower():
        path = "/user/repos?affiliation=owner,collaborator,organization_member&sort=pushed&per_page=100"
    else:
        path = f"/users/{user}/repos?type=owner&sort=pushed&per_page=100"
        if login:
            result["notes"].append(f"gh is logged in as {login}, not {user}: only {user}'s public repositories are visible")
        else:
            result["notes"].append("public repositories only - log in with `gh auth login` to include private ones")
    repos = client.get(path)
    if not isinstance(repos, list):
        raise RuntimeError("unexpected answer from GitHub")
    result["repos"] = len(repos)
    now = datetime.datetime.now(datetime.timezone.utc)
    recent = [r for r in repos if r.get("pushed_at") and (now - parse_time(r["pushed_at"])).days < days]
    result["recent"] = [{"repo": r["full_name"], "pushed_at": r["pushed_at"], "private": r.get("private", False)} for r in recent]

    n, start = bursts([parse_time(r["pushed_at"]) for r in recent])
    if n > BURST_REPOS:
        when = start.astimezone().strftime("%Y-%m-%d %H:%M")
        result["findings"].append(["WARNING", user, f"{n} repositories were pushed within one hour (from {when}). "
                                   "The worm pushes into many repositories at once - if this wasn't you, act now"])

    seen = load_seen()
    todo = [r for r in recent if rescan or seen.get(r["full_name"]) != r["pushed_at"]]
    result["unchanged"] = len(recent) - len(todo)
    for r in todo[:max_repos]:
        if r.get("size", 0) > 200_000:   # KB; very large repositories are skipped to keep the check quick
            result["notes"].append(f"{r['full_name']}: skipped (larger than 200 MB)")
            continue
        branch = r.get("default_branch") or "HEAD"
        tmp = tempfile.mkdtemp(prefix="polinrider-gh-")
        try:
            blob = client.get(f"/repos/{r['full_name']}/tarball/{branch}", binary=True, limit=MAX_ARCHIVE)
            safe_extract(blob, tmp)
            s = cr.Scan(tmp)
            s.walk()
            result["scanned"].append(r["full_name"])
            if s.findings:
                seen.pop(r["full_name"], None)        # keep re-checking until it's clean
            else:
                seen[r["full_name"]] = r["pushed_at"]
            for sev, rule, rel, detail in s.findings:
                result["findings"].append([sev, f"{r['full_name']} ({branch})", f"{rel} - {detail}"])
        except RuntimeError as e:
            result["notes"].append(f"{r['full_name']}: not scanned ({e})")
        except (tarfile.TarError, OSError) as e:
            result["notes"].append(f"{r['full_name']}: not scanned ({e.__class__.__name__})")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    save_seen(seen)
    if len(todo) > max_repos:
        result["notes"].append(f"{len(todo) - max_repos} more recently pushed repositories will be scanned next time (limit {max_repos} per run)")
    return result


def main(argv):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 3
    user = argv[0].strip().lstrip("@")
    if not user.replace("-", "").isalnum() or len(user) > 39:
        print(f"github_check: '{user}' is not a valid GitHub username", file=sys.stderr)
        return 3
    days = int(argv[argv.index("--days") + 1]) if "--days" in argv else 7
    max_repos = int(argv[argv.index("--max-repos") + 1]) if "--max-repos" in argv else 15
    try:
        res = check(user, days, max_repos, "--rescan" in argv)
    except (RuntimeError, ValueError) as e:
        if "--json" in argv:
            print(json.dumps({"user": user, "error": str(e)}))
        else:
            print(f"github_check: could not check {user}: {e}", file=sys.stderr)
        return 3
    danger = any(f[0] == "DANGER" for f in res["findings"])
    code = 1 if danger else (2 if res["findings"] else 0)
    res["exit"] = code
    if "--json" in argv:
        print(json.dumps(res))
        return code
    print(f"GitHub account {user} ({'via gh, incl. private' if res['source'] == 'gh' else 'public repositories'}): "
          f"{res['repos']} repositories, {len(res['recent'])} pushed in the last {days} days, {len(res['scanned'])} scanned"
          + (f", {res['unchanged']} unchanged since they were last scanned clean" if res.get("unchanged") else ""))
    for sev, where, detail in res["findings"]:
        print(f"  {'🛑' if sev == 'DANGER' else '⚠️ '} {where}: {detail}")
    for note in res["notes"]:
        print(f"  · {note}")
    if code == 0:
        print("  ✅ no signs of malware")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
