#!/usr/bin/env python3
"""github_protect — stop a stolen token from force-pushing your repositories, with a GitHub ruleset.

Part of Ardvane (MIT License). Python 3.8+, no dependencies.

The PolinRider worm force-pushes into every repository a stolen token can reach. A ruleset on the default branch that
blocks force pushes (and deleting the branch) turns that into a refused push. This tool adds one, and can remove it.

  github_protect.py list                      repositories the last GitHub audit found open to force pushes
  github_protect.py protect REPO ... | --all  add the ruleset  (--dry-run shows what would be sent, changes nothing)
  github_protect.py undo REPO ...             remove the ruleset Ardvane added

It uses your signed-in GitHub CLI (`gh`); your token stays inside gh. It only ever touches repositories you administer,
and every ruleset it adds is remembered in ~/.checkrepo/github-rulesets.json so it can be undone.

What the ruleset does not do: someone holding a token with admin rights on the repository can still delete the ruleset.
That takes an extra step and shows in the repository's audit log, and the next Ardvane audit lists the repository as
open again. If you push a cleaned history (Ardvane's History page) to a protected repository, undo the ruleset first and
add it back afterwards: a clean-up is a force push.

Exit code: 0 done, 1 a repository could not be changed, 3 not possible (no gh, bad input).
"""
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kitlib import DEST, read_json, safe_output, write_json  # noqa: E402
import github_check as gc  # noqa: E402

RULESET_NAME = "Ardvane: block force pushes"
RULESETS_FILE = os.path.join(DEST, "github-rulesets.json")


def ruleset_body():
    """The ruleset sent to GitHub: the default branch, force pushes and deletion blocked, nobody exempt."""
    return {"name": RULESET_NAME, "target": "branch", "enforcement": "active",
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            "rules": [{"type": "non_fast_forward"}, {"type": "deletion"}],
            "bypass_actors": []}


def exposed():
    """Repositories the last account audit found open to force pushes, minus the ones protected since."""
    done = read_json(RULESETS_FILE, {})
    return [r for r in read_json(gc.AUDIT_FILE, {}).get("exposed", [])
            if isinstance(r, dict) and r.get("repo") and r["repo"].lower() not in {k.lower() for k in done}]


def protected():
    """Repositories Ardvane added its ruleset to: {repo: {id, added}}."""
    return {k: v for k, v in read_json(RULESETS_FILE, {}).items() if isinstance(v, dict) and v.get("id")}


def _forget(repo):
    """Take a protected repository out of the audit's open list (and its note), so the dashboard updates at once."""
    cache = read_json(gc.AUDIT_FILE, {})
    if cache:
        cache["exposed"] = [r for r in cache.get("exposed", []) if r.get("repo", "").lower() != repo.lower()]
        cache["notes"] = [n for n in cache.get("notes", []) if "let a stolen token force-push" not in n]
        if cache["exposed"]:
            cache["notes"].append(f"{len(cache['exposed'])} of {cache.get('admin', '?')} repositories you administer let a stolen "
                                  f"token force-push the default branch (e.g. {', '.join(r['repo'] for r in cache['exposed'][:3])}) "
                                  "- add a ruleset that blocks force pushes (`ardvane branches protect --all` does it)")
        write_json(gc.AUDIT_FILE, cache)


def _remember(repo, ruleset_id):
    done = read_json(RULESETS_FILE, {})
    done[repo] = {"id": ruleset_id, "added": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M")}
    write_json(RULESETS_FILE, done)


def protect_one(client, repo, dry_run=False):
    """Add the ruleset to one repository. {repo, status, message}; status: protected, already, dry-run or failed."""
    name = gc.parse_repo(repo)
    try:
        info = client.get(f"/repos/{name}")
        if not (info.get("permissions") or {}).get("admin"):
            return {"repo": name, "status": "failed", "message": "you aren't an administrator of this repository, so GitHub won't let you add rules"}
        if info.get("archived"):
            return {"repo": name, "status": "failed", "message": "the repository is archived (read-only already)"}
        branch = info.get("default_branch") or "main"
        rules = client.get(f"/repos/{name}/rules/branches/{branch}")
        if isinstance(rules, list) and any(isinstance(x, dict) and x.get("type") == "non_fast_forward" for x in rules):
            return {"repo": name, "status": "already", "message": f"force pushes to {branch} are already blocked"}
        if dry_run:
            return {"repo": name, "status": "dry-run", "message": f"would add the ruleset '{RULESET_NAME}' to {branch}"}
        made = client.send("POST", f"/repos/{name}/rulesets", ruleset_body())
        if not isinstance(made, dict) or not made.get("id"):
            return {"repo": name, "status": "failed", "message": "GitHub accepted the request but returned no ruleset"}
        _remember(name, made["id"])
        _forget(name)
        return {"repo": name, "status": "protected", "message": f"force pushes to {branch} are now blocked"}
    except gc.RateLimited:
        raise
    except RuntimeError as e:
        msg = str(e)
        if "upgrade" in msg.lower() or "pro" in msg.lower().split():
            msg += " (rules on private repositories need a paid GitHub plan)"
        return {"repo": name, "status": "failed", "message": msg[:240]}


def undo_one(client, repo):
    name = gc.parse_repo(repo)
    entry = next((v for k, v in protected().items() if k.lower() == name.lower()), None)
    if not entry:
        return {"repo": name, "status": "failed", "message": "Ardvane didn't add a ruleset to this repository"}
    try:
        client.send("DELETE", f"/repos/{name}/rulesets/{int(entry['id'])}")
    except RuntimeError as e:
        if "not found" not in str(e).lower() and "404" not in str(e):
            return {"repo": name, "status": "failed", "message": str(e)[:240]}      # already gone on GitHub: fine, forget it
    done = read_json(RULESETS_FILE, {})
    done = {k: v for k, v in done.items() if k.lower() != name.lower()}
    write_json(RULESETS_FILE, done)
    return {"repo": name, "status": "removed", "message": "the ruleset was removed: force pushes are possible again"}


def client_for_changes():
    login = gc.gh_login()
    if not login or login == gc.CI_LOGIN:
        raise RuntimeError("log in with `gh auth login` first: changing GitHub needs your signed-in GitHub CLI")
    return gc.Client(use_gh=True)


def run(action, repos, dry_run=False):
    """The results of protecting (or undoing) several repositories, one at a time."""
    client = client_for_changes()
    results = []
    for repo in repos:
        results.append(undo_one(client, repo) if action == "undo" else protect_one(client, repo, dry_run))
    return results


def main(argv):
    safe_output()
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 3
    action, args = argv[0], argv[1:]
    if action == "list":
        rows, mine = exposed(), protected()
        if not rows and not mine:
            print("Nothing to do: the last GitHub audit found no repository open to force pushes (run a scan with the GitHub check on first).")
        for r in rows:
            print(f"  open        {r['repo']}  ({r['branch']}{', private' if r.get('private') else ''})")
        for k, v in mine.items():
            print(f"  protected   {k}  (ruleset added {v.get('added', '?')})")
        return 0
    if action not in ("protect", "undo"):
        print(f"github_protect: unknown action '{action}'", file=sys.stderr)
        return 3
    flags = {a for a in args if a.startswith("--")}
    names = [a for a in args if not a.startswith("--")]
    if "--all" in flags and action == "protect":
        names = [r["repo"] for r in exposed()]
        if not names:
            print("Nothing to protect: no repository is listed as open to force pushes.")
            return 0
    if not names:
        print(f"github_protect: name the repositories (owner/name), or use --all with protect", file=sys.stderr)
        return 3
    try:
        results = run(action, names, "--dry-run" in flags)
    except (RuntimeError, ValueError) as e:
        print(f"github_protect: {e}", file=sys.stderr)
        return 3
    for r in results:
        print(f"  {'✅' if r['status'] in ('protected', 'already', 'removed') else '·' if r['status'] == 'dry-run' else '❌'} {r['repo']}: {r['message']}")
    return 1 if any(r["status"] == "failed" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
