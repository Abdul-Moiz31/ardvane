#!/usr/bin/env python3
"""history - scan a repository's whole history, and clean malware out of it. Part of Ardvane (MIT License).

Python 3.8+, standard library and git only (no git-filter-repo needed).

  history.py scan PATH | OWNER/NAME [--json]
      Every file version on every branch and tag (and, for a local clone, its remote branches) is checked with the
      same rules as checkrepo. Finds malware that a scan of the latest files misses: in an old commit, on a branch
      nobody opens, in a tag. Read-only. A GitHub repository is cloned into a temporary folder and deleted afterwards.

  history.py clean OWNER/NAME [--json]
      Prepares a clean history - nothing is pushed:
        1. a complete backup (git clone --mirror) is kept in ~/.checkrepo/history/<repo>-<time>/backup.git;
        2. every commit of every branch and tag is rewritten: files that are only malware are left out (the file keeps
           the version it had before, or never appears), files that are also yours (a build config, .gitignore,
           package.json, an AI instructions file) lose only the injected part;
        3. the new history is scanned again and must be clean; a list of what changed on each branch is saved.
      Only for repositories your GitHub login administers.

  history.py push WORKDIR [--json]
      Pushes a prepared clean history (after a person confirmed it), with --force-with-lease and --atomic: if anyone
      pushed in the meantime, nothing is pushed. Pull-request refs, forks and other people's clones keep the old
      history - see docs/after-a-scan/clean-github-repos.md.

Exit code: 0 clean / done, 1 malware found (scan), 2 warnings only, 3 could not run.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kitlib import DEST, load_checkrepo, safe_output, write_json  # noqa: E402

WORK_ROOT = os.path.join(DEST, "history")
REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
MAX_BLOB = 5 * 1024 * 1024          # file versions checked, as checkrepo reads files whole up to this size
MAX_BLOBS = 50_000                  # distinct file versions checked per repository
SKIP_NAMES = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock")   # every version is huge
# git must never run anything from the repository it reads or rewrites
SAFE = ["-c", "core.hooksPath=" + os.devnull, "-c", "core.fsmonitor=false", "-c", "protocol.ext.allow=never",
        "-c", "protocol.file.allow=user", "-c", "advice.detachedHead=false", "-c", "gc.auto=0"]


def git(args, cwd=None, input=None, timeout=3600, check=True):
    r = subprocess.run(["git"] + SAFE + args, cwd=cwd, input=input, capture_output=True, timeout=timeout,
                       env=dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1"))
    if check and r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).decode("utf-8", "replace").strip()[-400:] or f"git {args[0]} failed")
    return r


def gh_exe():
    return shutil.which("gh")


def clone_url(name):
    """Where owner/name lives: GitHub, or a GitHub Enterprise server set in ARDVANE_GITHUB_URL."""
    base = os.environ.get("ARDVANE_GITHUB_URL", "https://github.com/").rstrip("/") + "/"
    return f"{base}{name}.git"


def credential_args():
    """Let git use the GitHub CLI's login for https, so private repositories work without another password."""
    return ["-c", "credential.helper=", "-c", "credential.helper=!" + gh_exe() + " auth git-credential"] if gh_exe() else []


def say(event, **kw):
    """Progress for the dashboard: one JSON object per line on stderr (stdout carries the result)."""
    sys.stderr.write(json.dumps(dict(kw, event=event)) + "\n")
    sys.stderr.flush()


# ---------------------------------------------------------------------------------------------- scanning
def blobs(git_dir):
    """{blob sha: first path it was seen at} for every file version reachable from any ref."""
    out = git(["--git-dir", git_dir, "rev-list", "--objects", "--all", "--filter=object:type=blob",
               "--filter-provided-objects"]).stdout.decode("utf-8", "surrogateescape")
    seen = {}
    for line in out.splitlines():
        sha, _, path = line.partition(" ")
        if path and sha not in seen:
            seen[sha] = path
    return seen


def sizes(git_dir, shas):
    out = git(["--git-dir", git_dir, "cat-file", "--batch-check=%(objectname) %(objectsize)"],
              input="\n".join(shas).encode() + b"\n").stdout.decode()
    return {s: int(n) for s, n in (l.split() for l in out.splitlines() if len(l.split()) == 2 and l.split()[1].isdigit())}


def read_blobs(git_dir, shas):
    """{sha: bytes} read in one git process."""
    data = git(["--git-dir", git_dir, "cat-file", "--batch"], input="\n".join(shas).encode() + b"\n").stdout
    out, i = {}, 0
    while i < len(data):
        nl = data.index(b"\n", i)
        head = data[i:nl].decode().split()
        if len(head) < 3:                                       # "<sha> missing"
            i = nl + 1
            continue
        n = int(head[2])
        out[head[0]] = data[nl + 1:nl + 1 + n]
        i = nl + 1 + n + 1
    return out


def scan_git_dir(git_dir, label=""):
    """Check every distinct file version in the history. Returns a result dict (see main)."""
    cr = load_checkrepo()
    say("phase", text="listing every file version in the history")
    allb = blobs(git_dir)
    refs = [l.split()[1] for l in git(["--git-dir", git_dir, "for-each-ref", "--format=%(objectname) %(refname)"]).stdout.decode().splitlines() if " " in l]
    commits = int(git(["--git-dir", git_dir, "rev-list", "--all", "--count"]).stdout.decode().strip() or 0)
    result = {"target": label or git_dir, "refs": len(refs), "commits": commits, "versions": len(allb), "checked": 0,
              "findings": [], "notes": []}
    named = {sha: path for sha, path in allb.items() if cr.IMPLANT_NAME_RE.search(path) or cr.WORM_NAME_RE.search(path)}
    wanted = [sha for sha, path in allb.items()
              if (cr.Kind(path).interesting or sha in named) and os.path.basename(path).lower() not in SKIP_NAMES]
    size = sizes(git_dir, wanted)
    big = [s for s in wanted if size.get(s, 0) > MAX_BLOB and s not in named]
    wanted = [s for s in wanted if s not in big]
    if len(wanted) > MAX_BLOBS:
        result["notes"].append(f"only the first {MAX_BLOBS} of {len(wanted)} file versions were checked")
        wanted = wanted[:MAX_BLOBS]
    if big:
        result["notes"].append(f"{len(big)} file versions over {MAX_BLOB // 1024 // 1024} MB were not checked")
    result["notes"].append("lockfile versions are not checked in history (the latest lockfile is, by checkrepo)")
    say("phase", text=f"checking {len(wanted)} file versions from {commits} commits")
    tmp = tempfile.mkdtemp(prefix="ardvane-history-")
    try:
        for start in range(0, len(wanted), 2000):
            chunk = wanted[start:start + 2000]
            for sha, data in read_blobs(git_dir, chunk).items():
                parts = [p for p in allb[sha].split("/") if p not in ("", ".", "..")]
                dest = os.path.join(tmp, sha, *parts)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as f:
                    f.write(data)
            say("progress", done=min(start + 2000, len(wanted)), total=len(wanted))
        say("phase", text="checking each file version at its own path")
        for sha in os.listdir(tmp):                            # one small scan per version: path rules see the real path
            s = cr.Scan(os.path.join(tmp, sha), all_files=True)
            s.walk()
            for sev, rule, path, detail in s.findings:
                if rule != "scan-error":
                    result["findings"].append({"severity": sev, "rule": rule, "path": path, "detail": detail, "blob": sha})
        result["checked"] = len(wanted)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # where each bad file version lives: is it in the current files of a branch or tag, or only in older commits?
    tips = [l for l in git(["--git-dir", git_dir, "for-each-ref", "--format=%(refname)", "refs/heads", "refs/tags", "refs/remotes"]).stdout.decode().split()
            if not l.endswith("/HEAD")]
    for f in result["findings"]:
        query = "\n".join(f"{t}:{f['path']}" for t in tips).encode() + b"\n"
        found = git(["--git-dir", git_dir, "cat-file", "--batch-check=%(objectname)"], input=query, check=False).stdout.decode().split("\n")
        live = [t for t, sha in zip(tips, found) if sha.strip() == f["blob"]]
        f["live_refs"] = [re.sub(r"^refs/(heads|tags|remotes)/", "", t) for t in live]
        log = git(["--git-dir", git_dir, "log", "--all", "--format=%H", "--find-object=" + f["blob"]]).stdout.decode().split()
        removed, added = [], []
        for c in log[:20]:
            here = git(["--git-dir", git_dir, "rev-parse", "--verify", "--quiet", f"{c}:{f['path']}"], check=False).stdout.decode().strip()
            (added if here == f["blob"] else removed).append(c[:10])
        f["added_in"], f["removed_in"] = added, removed
        f["commits"] = [c[:10] for c in log[:20]]
        f["commit_count"] = len(log)
        holders = set()
        for c in log[:5]:
            out = git(["--git-dir", git_dir, "for-each-ref", "--contains", c, "--format=%(refname:short)",
                       "refs/heads", "refs/tags", "refs/remotes"]).stdout.decode().split()
            holders.update(r for r in out if not r.endswith("/HEAD"))
        f["history_refs"] = len(holders)
        f["refs"] = sorted(holders, key=lambda r: (not r.startswith("origin/"), r))[:30]
        f["where"] = (f"in the current files of {len(live)} branch(es)/tag(s): " + ", ".join(f["live_refs"][:4]) if live else
                      "only in older commits - removed in " + (", ".join(removed[:3]) or "a later commit") +
                      f", still in the history of {len(holders)} branch(es)/tag(s)")
    return result


def scan(target):
    """Scan a local repository (path) or a GitHub repository (owner/name, cloned into a temporary folder)."""
    if os.path.isdir(os.path.expanduser(target)):
        path = os.path.abspath(os.path.expanduser(target))
        git_dir = git(["-C", path, "rev-parse", "--absolute-git-dir"]).stdout.decode().strip()
        return scan_git_dir(git_dir, path)
    if not REPO_RE.match(target):
        raise ValueError("give a local repository folder or a GitHub repository as owner/name")
    tmp = tempfile.mkdtemp(prefix="ardvane-history-clone-")
    try:
        say("phase", text=f"downloading the history of {target}")
        git(credential_args() + ["clone", "--bare", "--quiet", clone_url(target), os.path.join(tmp, "repo.git")])
        return scan_git_dir(os.path.join(tmp, "repo.git"), target)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------------------------- cleaning
def plan_actions(findings):
    """{blob: ("delete", None) | ("cut", how)} for the DANGER findings that can be cleaned, and the ones that can't."""
    import autofix                      # the same decisions the fixer makes for the working copy
    cr = load_checkrepo()
    actions, manual = {}, []
    for f in findings:
        if f["severity"] != "DANGER" or f["blob"] in actions:
            continue
        name = os.path.basename(f["path"]).lower()
        cut = autofix.CUT.get(f["rule"])
        if f["rule"] == "ai-cli-abuse" and name != "package.json":
            cut = None
        if f["rule"] == "campaign-marker":
            cut = None
            text = f.get("text")
            if text is not None:
                left = autofix._cut(text, "hidden", cr)
                cut = "hidden" if left != text and not cr.marker_hits(left) else None
        if cut:
            actions[f["blob"]] = ("cut", cut)
        elif f["rule"] in autofix.QUARANTINE_RULES | {"worm-file", "implant-file"} and name not in autofix.NEVER_QUARANTINE:
            actions[f["blob"]] = ("delete", None)
        else:
            manual.append(f)
    return actions, manual


class Stream:
    """git fast-export output, read command by command (binary-safe: data blocks are read by their length)."""

    def __init__(self, raw):
        self.raw, self.i = raw, 0

    def line(self):
        if self.i >= len(self.raw):
            return None
        nl = self.raw.find(b"\n", self.i)
        nl = len(self.raw) if nl < 0 else nl
        out, self.i = self.raw[self.i:nl], nl + 1
        return out

    def take(self, n):
        out, self.i = self.raw[self.i:self.i + n], self.i + n
        return out


def rewrite(git_dir, actions, cr):
    """Rewrite every branch and tag of `git_dir` in place: blobs to cut get new content; file changes that bring in a
    blob to delete are dropped from the commits (the path keeps its previous version, or never appears)."""
    import autofix
    exported = git(["--git-dir", git_dir, "fast-export", "--all", "--show-original-ids", "--signed-commits=strip",
                    "--signed-tags=strip", "--reencode=yes", "--use-done-feature"], timeout=7200).stdout
    st, out = Stream(exported), []
    mark_of_blob, drop_marks, changed = {}, set(), 0
    current_mark = None
    while True:
        line = st.line()
        if line is None:
            break
        if line == b"blob":
            out.append(line)
            current_mark = None
            continue
        if line.startswith(b"mark :"):
            current_mark = line[5:].decode()
            out.append(line)
            continue
        if line.startswith(b"original-oid "):
            oid = line[13:].decode()
            if current_mark:
                mark_of_blob[current_mark] = oid
                if actions.get(oid, (None,))[0] == "delete":
                    drop_marks.add(current_mark)
            out.append(line)
            continue
        if line.startswith(b"data "):
            n = int(line[5:])
            data = st.take(n)
            if st.raw[st.i:st.i + 1] == b"\n":                # the optional newline after a data block (join adds it back)
                st.i += 1
            oid = mark_of_blob.get(current_mark) if current_mark else None
            act = actions.get(oid) if oid else None
            if act and act[0] == "cut":
                text = data.decode("utf-8", "surrogateescape")
                new = autofix._cut(text, act[1], cr).encode("utf-8", "surrogateescape")
                if new != data:
                    data, changed = new, changed + 1
            out.append(b"data " + str(len(data)).encode() + b"\n" + data)
            continue
        if line.startswith(b"M "):
            parts = line.split(b" ", 3)
            if len(parts) == 4 and parts[2].startswith(b":") and parts[2].decode() in drop_marks:
                changed += 1
                continue                                     # this commit no longer adds / changes the malware file
            out.append(line)
            continue
        if line.startswith((b"commit ", b"tag ", b"reset ")):
            current_mark = None
        out.append(line)
    stream = b"\n".join(out) + b"\n"
    git(["--git-dir", git_dir, "fast-import", "--force", "--quiet"], input=stream, timeout=7200)
    return changed


def refs_of(git_dir):
    out = git(["--git-dir", git_dir, "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads", "refs/tags"]).stdout.decode()
    return dict(reversed(l.split(" ", 1)) for l in out.splitlines() if " " in l)


def can_administer(name):
    """True if the GitHub CLI's login may rewrite `name` (admin on it). False without gh or access."""
    if not gh_exe():
        return False
    r = subprocess.run([gh_exe(), "api", f"repos/{name}", "--jq", ".permissions.admin"], capture_output=True, text=True, timeout=30)
    return r.returncode == 0 and r.stdout.strip() == "true"


def clean(target, remote=None, check_owner=True):
    """Prepare a clean history for a GitHub repository (or, for tests, any `remote`). Nothing is pushed."""
    if remote is None:
        if not REPO_RE.match(target):
            raise ValueError("give the GitHub repository as owner/name")
        if check_owner and not can_administer(target):
            raise PermissionError(f"your GitHub login doesn't administer {target}: only the owner can rewrite its history "
                                  "(log in with `gh auth login`, or ask the owner)")
        remote = clone_url(target)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    work = os.path.join(WORK_ROOT, re.sub(r"[^\w.-]+", "__", target) + "-" + stamp + "-" + os.urandom(3).hex())
    os.makedirs(work, mode=0o700)
    backup, repo = os.path.join(work, "backup.git"), os.path.join(work, "clean.git")
    say("phase", text="making a complete backup of the repository")
    git(credential_args() + ["clone", "--mirror", "--quiet", remote, backup])
    git(["clone", "--bare", "--quiet", backup, repo])
    git(["--git-dir", repo, "remote", "set-url", "origin", remote])
    before = refs_of(repo)
    say("phase", text="scanning the history")
    found = scan_git_dir(repo, target)
    texts = read_blobs(repo, [f["blob"] for f in found["findings"] if f["rule"] == "campaign-marker"])
    for f in found["findings"]:
        if f["blob"] in texts:
            f["text"] = texts[f["blob"]].decode("utf-8", "surrogateescape")
    actions, manual = plan_actions(found["findings"])
    plan = {"target": target, "remote": remote, "workdir": work, "created": time.time(), "before": before,
            "findings": [{k: v for k, v in f.items() if k != "text"} for f in found["findings"]],
            "manual": [{k: v for k, v in f.items() if k != "text"} for f in manual], "changes": {}, "pushed": False}
    if not actions:
        plan["state"] = "nothing-to-clean" if not manual else "manual-only"
        write_json(os.path.join(work, "plan.json"), plan)
        return plan
    say("phase", text=f"rewriting {found['commits']} commits on {len(before)} branches and tags")
    plan["edits"] = rewrite(repo, actions, load_checkrepo())
    after = refs_of(repo)
    say("phase", text="checking the new history")
    again = scan_git_dir(repo, target)
    left = [f for f in again["findings"] if f["severity"] == "DANGER" and f["blob"] not in {m["blob"] for m in manual}]
    for ref, old in before.items():
        new = after.get(ref)
        if new and new != old:
            diff = git(["--git-dir", repo, "diff", "--name-status", old, new], check=False).stdout.decode("utf-8", "replace").splitlines()
            plan["changes"][ref] = {"old": old, "new": new, "files": diff[:200]}
    plan["after"] = after
    plan["left"] = left
    plan["state"] = "ready" if plan["changes"] and not left else ("still-infected" if left else "unchanged")
    write_json(os.path.join(work, "plan.json"), plan)
    return plan


def push(workdir):
    """Push a prepared clean history. Refused when anyone pushed since it was prepared (--force-with-lease, atomic)."""
    with open(os.path.join(workdir, "plan.json"), encoding="utf-8") as f:
        plan = json.load(f)
    if plan.get("state") != "ready":
        raise ValueError("this clean history isn't ready to push (" + str(plan.get("state")) + ")")
    if plan.get("pushed"):
        raise ValueError("already pushed")
    repo = os.path.join(workdir, "clean.git")
    leases = [f"--force-with-lease={ref}:{c['old']}" for ref, c in plan["changes"].items()]
    refspecs = [f"{c['new']}:{ref}" for ref, c in plan["changes"].items()]
    say("phase", text=f"pushing {len(refspecs)} rewritten branches and tags")
    r = git(credential_args() + ["--git-dir", repo, "push", "--atomic", "--porcelain"] + leases + [plan["remote"]] + refspecs, check=False)
    plan["push_output"] = (r.stdout + r.stderr).decode("utf-8", "replace")[-4000:]
    plan["pushed"] = r.returncode == 0
    plan["pushed_at"] = time.time() if plan["pushed"] else None
    write_json(os.path.join(workdir, "plan.json"), plan)
    if r.returncode != 0:
        raise RuntimeError("GitHub refused the push - nothing was changed. " + _push_hint(plan["push_output"]))
    return plan


def _push_hint(output):
    if "stale info" in output or "rejected" in output:
        return "Someone pushed since the clean history was prepared: prepare it again."
    if "protected branch" in output.lower() or "GH006" in output or "rule" in output.lower():
        return "A branch protection rule or ruleset blocks force-pushes: allow them briefly for this push, then turn them back on."
    return output.strip().splitlines()[-1] if output.strip() else ""


# ---------------------------------------------------------------------------------------------- command line
def main(argv):
    safe_output()
    as_json = "--json" in argv
    args = [a for a in argv if a != "--json"]
    try:
        if len(args) == 2 and args[0] == "scan":
            res = scan(args[1])
            danger = any(f["severity"] == "DANGER" for f in res["findings"])
            warn = any(f["severity"] == "WARNING" for f in res["findings"])
            if as_json:
                print(json.dumps(res))
            else:
                print(f"{res['target']}: {res['commits']} commits, {res['refs']} branches and tags, {res['checked']} file versions checked")
                for f in res["findings"]:
                    print(f"  {'🛑' if f['severity'] == 'DANGER' else '⚠️ '} {f['path']}: {f['detail']} - {f['where']}")
                for n in res["notes"]:
                    print("  note: " + n)
                print("  ✅ no malware in the history" if not res["findings"] else "")
            return 1 if danger else 2 if warn else 0
        if len(args) == 2 and args[0] == "clean":
            plan = clean(args[1])
            if as_json:
                print(json.dumps(plan))
            else:
                print(f"{plan['state']}: {len(plan['changes'])} branch(es)/tag(s) rewritten; review, then: history.py push {plan['workdir']}")
            return 0
        if len(args) == 2 and args[0] == "push":
            plan = push(args[1])
            print(json.dumps(plan) if as_json else f"pushed {len(plan['changes'])} rewritten branches and tags")
            return 0
    except (ValueError, PermissionError, RuntimeError, OSError, subprocess.SubprocessError) as e:
        print(json.dumps({"error": str(e)}) if as_json else f"history: {e}", file=sys.stdout if as_json else sys.stderr)
        return 3
    print(__doc__)
    return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
