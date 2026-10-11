#!/usr/bin/env python3
"""github_check — read-only check of a GitHub account, or of chosen repositories, for PolinRider-style activity.

Part of Ardvane (MIT License). Python 3.8+, no dependencies.

What it does (never changes anything on GitHub):
  1. Lists the account's repositories and the ones pushed recently.
  2. Warns when many repositories were pushed within one hour (the worm force-pushes into every repo it can reach).
  3. Downloads the default branch (or, with --all-branches, every branch) of each recently pushed repository as an
     archive into a temporary folder, scans it with checkrepo, and deletes the temporary folder. Nothing from the
     archive is ever run.
  4. Repositories named with --repo (yours or anyone's you can read) are scanned on every branch, however long ago
     they were pushed.

Access:
  - If the GitHub CLI (`gh`) is installed and logged in, it is used, so private repositories are checked too.
    Your token stays inside `gh`; this script never reads or stores it.
  - Otherwise the public API is used (public repositories only, 60 requests per hour).

Usage:
  github_check.py USERNAME [--days N] [--max-repos N] [--all-branches] [--json] [--rescan]
  github_check.py [USERNAME] --repo OWNER/NAME [--repo ...] [--json] [--rescan]
      a repository can be given as owner/name, a github.com URL or a git@github.com: address

Limits: every repository of the account is listed (all pages). An archive holds only the latest files of one branch,
not the history, so it is much smaller than the repository size GitHub shows. Archives are streamed to a temporary file
(not kept in memory), so size is limited only by free disk space: a download stops if it would leave less than 2 GB
free (hard cap 10 GB). Single files over 20 MB (videos, models, datasets) are not scanned; malware payloads are tiny.

Repositories already scanned clean are skipped until they receive a new push (remembered in
~/.checkrepo/github-seen.json); --rescan scans them again.
Exit code: 0 clean, 1 danger found, 2 warnings only, 3 could not check.
"""
import datetime
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kitlib import DEST, load_checkrepo, read_json, safe_output, write_json  # noqa: E402

API = "https://api.github.com"
GB = 1024 ** 3
MAX_ARCHIVE = MAX_EXTRACTED = 10 * GB  # hard caps; in practice free disk space is the limit
KEEP_FREE = 2 * GB                     # never fill the disk: stop when less than this would be left
MAX_FILE = 20 * 1024 * 1024            # bigger single files (videos, models, datasets) are not scanned
CHUNK = 1024 * 1024
DOWNLOAD_TIMEOUT = 30 * 60             # seconds, for one archive
PER_PAGE, MAX_PAGES = 100, 50          # lists: up to 5,000 repositories or branches
BURST_REPOS, BURST_WINDOW = 5, 3600
SEEN_FILE = os.path.join(DEST, "github-seen.json")
TMP_PREFIX = "ardvane-gh-"
RATE_LIMIT_HELP = ("GitHub's hourly limit for checks was reached - try again later"
                   ", or log in with `gh auth login` (it allows many more checks and includes private repositories)")


class RateLimited(RuntimeError):
    """GitHub refuses further requests for now: stop the whole check instead of failing repo by repo."""


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
        self.truncated = []                            # lists longer than MAX_PAGES pages (reported as notes)

    def get(self, path, limit=5 * 1024 * 1024):
        if self.gh:
            try:
                r = subprocess.run([self.gh, "api", "-H", "Accept: application/vnd.github+json", path],
                                   capture_output=True, timeout=180)
            except subprocess.TimeoutExpired:
                raise RuntimeError("GitHub did not answer within 3 minutes")
            if r.returncode != 0:
                gh_error((r.stderr or b"").decode("utf-8", "replace"), r.returncode)
            data = r.stdout
        else:
            req = urllib.request.Request(API + path, headers={"Accept": "application/vnd.github+json",
                                                              "User-Agent": "ardvane"})
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = resp.read(limit + 1)
            except urllib.error.HTTPError as e:
                http_error(e)
            except urllib.error.URLError as e:
                raise RuntimeError(f"no connection to GitHub ({e.reason})")
            except OSError as e:                                    # e.g. a read timeout
                raise RuntimeError(f"connection to GitHub failed ({e.__class__.__name__})")
        if len(data) > limit:
            raise RuntimeError("response too large")
        return json.loads(data.decode("utf-8"))

    def download(self, path, dest):
        """Stream an archive into the file `dest`. Stops when it gets too big for the free disk space, when the
        whole download takes longer than DOWNLOAD_TIMEOUT, or when GitHub/gh reports an error."""
        limit = space_limit(os.path.dirname(dest), MAX_ARCHIVE)
        if self.gh:
            p = subprocess.Popen([self.gh, "api", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            src = p.stdout
        else:
            p = None
            req = urllib.request.Request(API + path, headers={"User-Agent": "ardvane"})
            try:
                src = urllib.request.urlopen(req, timeout=120)          # per read, so a stalled connection ends
            except urllib.error.HTTPError as e:
                http_error(e)
            except urllib.error.URLError as e:
                raise RuntimeError(f"no connection to GitHub ({e.reason})")
        deadline = time.monotonic() + DOWNLOAD_TIMEOUT
        watchdog = threading.Timer(DOWNLOAD_TIMEOUT, p.kill) if p else None   # a pipe read can't time out by itself
        if watchdog:
            watchdog.daemon = True
            watchdog.start()
        size, problem = 0, None
        try:
            with open(dest, "wb") as out:
                while True:
                    try:
                        chunk = src.read(CHUNK)
                    except OSError as e:                            # socket timeout or reset
                        raise RuntimeError(f"download interrupted ({e.__class__.__name__})")
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > limit:
                        problem = too_big(limit)
                        break
                    if time.monotonic() > deadline:
                        problem = f"download took longer than {DOWNLOAD_TIMEOUT // 60} minutes"
                        break
                    out.write(chunk)
        finally:
            if watchdog:
                watchdog.cancel()
            if p and p.poll() is None and (problem or sys.exc_info()[0]):
                p.kill()                                   # never leave gh running after we stop reading
            src.close()
            err = p.stderr.read().decode("utf-8", "replace").strip() if p else ""
            code = p.wait() if p else 0
            if p:
                p.stderr.close()
        if problem:
            raise RuntimeError(problem)
        if code != 0:
            if time.monotonic() > deadline:
                raise RuntimeError(f"download took longer than {DOWNLOAD_TIMEOUT // 60} minutes")
            gh_error(err, code)
        return size

    def get_all(self, path):
        """Every item of a paged list (GitHub returns at most 100 per page)."""
        items = []
        for page in range(1, MAX_PAGES + 1):
            batch = self.get(f"{path}{'&' if '?' in path else '?'}per_page={PER_PAGE}&page={page}")
            if not isinstance(batch, list):
                raise RuntimeError("unexpected answer from GitHub")
            items += batch
            if len(batch) < PER_PAGE:
                break
        else:
            self.truncated.append(path)
        return items


def gh_error(stderr, code):
    msg = stderr.strip()
    if "rate limit" in msg.lower():
        raise RateLimited(RATE_LIMIT_HELP)
    raise RuntimeError(msg[:200] or f"gh api failed (exit code {code})")


def http_error(e):
    if e.code in (403, 429) and (e.headers.get("X-RateLimit-Remaining") == "0" or e.code == 429):
        raise RateLimited(RATE_LIMIT_HELP)
    raise RuntimeError("HTTP 404: not found" if e.code == 404 else f"GitHub returned HTTP {e.code}")


def remove_stale_temp(max_age=24 * 3600):
    """Temporary folders left behind by a check that was killed (e.g. the computer went to sleep)."""
    base = tempfile.gettempdir()
    try:
        names = os.listdir(base)
    except OSError:
        return
    for name in names:
        path = os.path.join(base, name)
        if name.startswith((TMP_PREFIX, "polinrider-gh-")):
            try:
                if time.time() - os.path.getmtime(path) > max_age:
                    shutil.rmtree(path, ignore_errors=True)
            except OSError:
                pass


def space_limit(folder, cap):
    """How many bytes may be written into `folder`: the cap, or less so that KEEP_FREE stays free."""
    limit = min(cap, shutil.disk_usage(folder).free - KEEP_FREE)
    if limit <= 0:
        raise RuntimeError(f"less than {KEEP_FREE // GB} GB free on this disk")
    return limit


def too_big(limit):
    return f"larger than {limit // GB} GB" if limit == MAX_ARCHIVE else \
        f"too large for the free disk space (Ardvane keeps {KEEP_FREE // GB} GB free)"


def parse_time(s):
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def safe_extract(archive, dest):
    """Extract regular files only; refuse absolute paths, '..', links and devices. Strips the top folder.
    `archive` is the archive's bytes or the path of an archive file.

    Never lets one file stop the scan of the others: a file that can't be written here (a name Windows forbids, a
    path that is too long) is counted and skipped. Files whose names differ only in upper/lower case (or Unicode
    form) would overwrite each other on macOS and Windows, which would let malware hide behind a harmless file, so
    each later one is extracted into its own `.ardvane-same-name-N` folder and scanned too.
    Stops (RuntimeError) before the extracted files would fill the disk.
    Returns {"too_large": n, "unwritable": n, "same_name": n}."""
    limit, total = space_limit(dest, MAX_EXTRACTED), 0
    counts = {"too_large": 0, "unwritable": 0, "same_name": 0}
    taken = set()
    real_dest = os.path.realpath(dest)
    opened = tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") if isinstance(archive, bytes) else \
        tarfile.open(archive, mode="r:gz")
    with opened as tf:
        for m in tf:
            parts = [x for x in m.name.replace("\\", "/").split("/")[1:] if x not in ("", ".")]  # drop top folder
            if not parts or not m.isfile() or m.name.startswith("/") or ".." in parts:
                continue
            if m.size > MAX_FILE:
                counts["too_large"] += 1
                continue
            total += m.size
            if total > limit:                                      # a "tar bomb" can't fill the disk
                raise RuntimeError("files " + too_big(limit))
            key = unicodedata.normalize("NFC", "/".join(parts)).casefold()
            root = dest
            if key in taken:
                counts["same_name"] += 1
                root = os.path.join(dest, f".ardvane-same-name-{counts['same_name']}")
            taken.add(key)
            target = os.path.join(root, *parts)
            if not os.path.realpath(target).startswith(real_dest + os.sep):
                continue
            src = tf.extractfile(m)
            if src is None:
                continue
            try:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
            except OSError:
                counts["unwritable"] += 1
    return counts


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
    return read_json(SEEN_FILE, {})


def save_seen(seen):
    try:
        write_json(SEEN_FILE, seen)
    except OSError:
        pass


def scan_branch(client, cr, repo, branch, result, maybe_empty=False):
    """Download one branch as an archive, scan it, delete it. Returns "clean", "found", "empty" or "error".
    Raises RateLimited, which ends the whole check."""
    where = f"{repo} ({branch})"
    tmp = tempfile.mkdtemp(prefix=TMP_PREFIX)
    archive, files = os.path.join(tmp, "archive.tar.gz"), os.path.join(tmp, "files")
    try:
        client.download(f"/repos/{repo}/tarball/{urllib.parse.quote(branch, safe='/')}", archive)
        os.makedirs(files)
        counts = safe_extract(archive, files)
        os.remove(archive)
        if counts["too_large"]:
            result["notes"].append(f"{where}: {counts['too_large']} file(s) over {MAX_FILE // (1024 * 1024)} MB not scanned")
        if counts["unwritable"]:
            result["notes"].append(f"{where}: {counts['unwritable']} file(s) could not be written on this computer "
                                   "(name or path not allowed here) and were not scanned")
        s = cr.Scan(files)
        s.walk()
        for sev, rule, rel, detail in s.findings:
            result["findings"].append([sev, where, f"{rel} - {detail}"])
        return "found" if s.findings else "clean"
    except RateLimited:
        raise
    except RuntimeError as e:
        if maybe_empty and ("404" in str(e) or "409" in str(e)):
            return "empty"                             # GitHub has no archive for a repository without commits
        result["notes"].append(f"{where}: not scanned ({e})")
    except (tarfile.TarError, OSError) as e:
        result["notes"].append(f"{where}: not scanned ({e.__class__.__name__})")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return "error"


def seen_ok(seen, repo, all_branches):
    """True if the repository was scanned clean at this push (a clean all-branches scan also covers default-only)."""
    v = seen.get(repo["full_name"], "")
    return v == repo["pushed_at"] + "|all" or (not all_branches and v == repo["pushed_at"])


USER_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
REPO_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9._-]{1,100}")
GITHUB_PREFIX_RE = re.compile(r"^(?:https?://(?:www\.)?github\.com/|(?:ssh://)?git@github\.com[:/])", re.I)


def parse_repo(text):
    """'owner/name' from owner/name, a github.com URL (any page of the repository) or a git@github.com: address.
    Raises ValueError for anything else - this is also what the dashboard uses to check what you type."""
    raw = str(text).strip()
    rest = GITHUB_PREFIX_RE.sub("", raw)
    parts = rest.split("?", 1)[0].split("#", 1)[0].strip("/").split("/")
    if len(parts) < 2 or (rest == raw and len(parts) != 2):    # a URL may go deeper (…/tree/main), a name may not
        raise ValueError(f"'{raw}' is not a GitHub repository (use owner/name or its github.com link)")
    name = parts[0] + "/" + re.sub(r"\.git$", "", parts[1], flags=re.I)
    if not REPO_NAME_RE.fullmatch(name) or parts[1] in (".", ".."):
        raise ValueError(f"'{raw}' is not a GitHub repository (use owner/name or its github.com link)")
    return name


def scan_repo(client, cr, repo, all_branches, result, seen):
    """Scan one repository - its default branch, or every branch - and remember it if clean.
    Returns "clean", "found" or "error". Raises RateLimited, which ends the whole check."""
    name = repo["full_name"]
    branches = [repo.get("default_branch") or "HEAD"]
    if all_branches:
        try:
            branches = [b["name"] for b in client.get_all(f"/repos/{name}/branches")] or branches
        except RateLimited:
            raise
        except RuntimeError as e:
            result["notes"].append(f"{name}: could not list branches ({e}), scanning the default branch only")
    outcomes = set()
    for branch in branches:
        outcomes.add(scan_branch(client, cr, name, branch, result, maybe_empty=not repo.get("size")))
        result["branches_scanned"] += 1
    if outcomes != {"error"}:
        result["scanned"].append(name)
    if outcomes <= {"clean", "empty"}:
        seen[name] = repo["pushed_at"] + ("|all" if all_branches else "")
        return "clean"
    seen.pop(name, None)                                  # keep re-checking until it's clean
    return "found" if "found" in outcomes else "error"


def check_listed(client, cr, names, rescan, result, seen):
    """Every branch of each repository named with --repo, unless it is unchanged since its last clean scan."""
    done = {n.lower() for n in result["scanned"]}
    for name in names:
        row = {"repo": name, "outcome": "", "branches": 0}
        result["listed"].append(row)
        if name.lower() in done:
            row["outcome"] = "scanned above"
            continue
        try:
            repo = client.get(f"/repos/{name}")
        except RateLimited:
            raise
        except RuntimeError as e:
            row["outcome"] = "error"
            hint = "not found, or your GitHub login can't see it" if "404" in str(e) or "not found" in str(e).lower() else str(e)
            # a repository you asked for that couldn't be checked must not look clean
            result["findings"].append(["WARNING", name, f"not scanned: {hint}"])
            continue
        row["repo"] = name = repo.get("full_name") or name           # GitHub's spelling
        if not rescan and repo.get("pushed_at") and seen_ok(seen, repo, all_branches=True):
            row["outcome"] = "unchanged"
            continue
        before = result["branches_scanned"]
        row["outcome"] = scan_repo(client, cr, repo, True, result, seen)
        row["branches"] = result["branches_scanned"] - before
        done.add(name.lower())


def check(user="", days=7, max_repos=15, rescan=False, all_branches=False, repos=()):
    cr = load_checkrepo()
    remove_stale_temp()
    login = gh_login()
    client = Client(use_gh=bool(login))
    result = {"user": user, "source": "gh" if login else "public", "repos": 0, "recent": [], "scanned": [],
              "branches_scanned": 0, "findings": [], "notes": [], "listed": []}
    seen = load_seen()
    try:
        if user:
            check_account(client, cr, user, login, days, max_repos, rescan, all_branches, result, seen)
        check_listed(client, cr, repos, rescan, result, seen)
    except RateLimited as e:
        result["notes"].append(f"stopped early: {e}")
    finally:
        save_seen(seen)
    if not login and repos and not user:          # (the account check already says so)
        result["notes"].append("public repositories only - log in with `gh auth login` to include private ones")
    for path in client.truncated:
        result["notes"].append(f"only the first {MAX_PAGES * PER_PAGE} items of {path.split('?')[0]} were checked")
    return result


def check_account(client, cr, user, login, days, max_repos, rescan, all_branches, result, seen):
    """The account's recently pushed repositories, and the worm's signature: many pushed within one hour."""
    # sorted by name, not by push time: a push during the listing can't shift repositories between pages
    if login and login.lower() == user.lower():
        path = "/user/repos?affiliation=owner,collaborator,organization_member&sort=full_name"
    else:
        path = f"/users/{user}/repos?type=owner&sort=full_name"
        if login:
            result["notes"].append(f"gh is logged in as {login}, not {user}: only {user}'s public repositories are visible")
        else:
            result["notes"].append("public repositories only - log in with `gh auth login` to include private ones")
    repos = list({r["full_name"]: r for r in client.get_all(path) if isinstance(r, dict) and r.get("full_name")}.values())
    repos.sort(key=lambda r: r.get("pushed_at") or "", reverse=True)          # most recently pushed first
    result["repos"] = len(repos)
    now = datetime.datetime.now(datetime.timezone.utc)
    recent = [r for r in repos if r.get("pushed_at") and (now - parse_time(r["pushed_at"])).days < days]
    result["recent"] = [{"repo": r["full_name"], "pushed_at": r["pushed_at"], "private": r.get("private", False)} for r in recent]

    n, start = bursts([parse_time(r["pushed_at"]) for r in recent])
    if n > BURST_REPOS:
        when = start.astimezone().strftime("%Y-%m-%d %H:%M")
        result["findings"].append(["WARNING", user, f"{n} repositories were pushed within one hour (from {when}). "
                                   "The worm pushes into many repositories at once - if this wasn't you, act now"])

    todo = [r for r in recent if rescan or not seen_ok(seen, r, all_branches)]
    result["unchanged"] = len(recent) - len(todo)
    done = 0
    try:
        for r in todo[:max_repos]:
            scan_repo(client, cr, r, all_branches, result, seen)
            done += 1
    finally:
        if len(todo) > done:
            result["notes"].append(f"{len(todo) - done} more recently pushed repositories will be scanned next time"
                                   + (f" (limit {max_repos} per run)" if done == max_repos else ""))


VALUE_FLAGS = ("--days", "--max-repos", "--repo")


def parse_args(argv):
    """{user, repos, days, max_repos, flags}; raises ValueError with a message for the user."""
    opts = {"user": "", "repos": [], "days": 7, "max_repos": 15, "flags": set()}
    positional, i = [], 0
    while i < len(argv):
        a = argv[i]
        if a in VALUE_FLAGS:
            if i + 1 >= len(argv):
                raise ValueError(f"{a} needs a value")
            v = argv[i + 1]
            if a == "--repo":
                name = parse_repo(v)
                if name.lower() not in {r.lower() for r in opts["repos"]}:
                    opts["repos"].append(name)
            elif not v.isdigit() or int(v) < 1:
                raise ValueError(f"{a} needs a whole number of 1 or more")
            else:
                opts["days" if a == "--days" else "max_repos"] = int(v)
            i += 2
            continue
        if a.startswith("--"):
            opts["flags"].add(a)
        else:
            positional.append(a)
        i += 1
    if positional:
        opts["user"] = positional[0].strip().lstrip("@")
        if not USER_RE.fullmatch(opts["user"]):
            raise ValueError(f"'{opts['user']}' is not a valid GitHub username")
    if not opts["user"] and not opts["repos"]:
        raise ValueError("name a GitHub username, or repositories with --repo owner/name")
    return opts


def main(argv):
    safe_output()
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 3
    try:
        o = parse_args(argv)
    except ValueError as e:
        print(f"github_check: {e}", file=sys.stderr)
        return 3
    user, as_json, all_branches = o["user"], "--json" in o["flags"], "--all-branches" in o["flags"]
    what = user or ", ".join(o["repos"])
    try:
        res = check(user, o["days"], o["max_repos"], "--rescan" in o["flags"], all_branches, o["repos"])
    except (RuntimeError, ValueError) as e:
        if as_json:
            print(json.dumps({"user": user, "repos_listed": o["repos"], "error": str(e)}))
        else:
            print(f"github_check: could not check {what}: {e}", file=sys.stderr)
        return 3
    danger = any(f[0] == "DANGER" for f in res["findings"])
    code = 1 if danger else (2 if res["findings"] else 0)
    res["exit"] = code
    if as_json:
        print(json.dumps(res))
        return code
    access = "via gh, incl. private" if res["source"] == "gh" else "public repositories"
    if user:
        print(f"GitHub account {user} ({access}): {res['repos']} repositories, {len(res['recent'])} pushed in the last "
              f"{o['days']} days, {len(res['scanned']) - sum(1 for r in res['listed'] if r['branches'])} scanned"
              + (f" ({res['branches_scanned']} branches)" if all_branches else "")
              + (f", {res['unchanged']} unchanged since they were last scanned clean" if res.get("unchanged") else ""))
    if res["listed"]:
        print(f"Repositories you listed ({access if not user else 'every branch'}):")
        for r in res["listed"]:
            print(f"  · {r['repo']}: " + {"clean": f"scanned {r['branches']} branch(es)", "found": f"scanned {r['branches']} branch(es) - see below",
                                          "unchanged": "unchanged since its last clean scan", "scanned above": "scanned with the account",
                                          "error": "not scanned (see the warning below)"}.get(r["outcome"], r["outcome"]))
    for sev, where, detail in res["findings"]:
        print(f"  {'🛑' if sev == 'DANGER' else '⚠️ '} {where}: {detail}")
    for note in res["notes"]:
        print(f"  · {note}")
    if code == 0:
        print("  ✅ no signs of malware")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
