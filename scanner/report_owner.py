#!/usr/bin/env python3
"""report_owner — write the report a repository's owner needs when you find malware in a repository they own.

Part of Ardvane (MIT License). Python 3.8+, no dependencies.

When a repository shared with you (a teammate's, a client's, a friend's) carries malware, the owner is usually unaware.
This tool scans the repository on GitHub (every branch, read-only, nothing is cloned or run) and writes a short report
you can send them: what was found and where, why it matters, and what they should do, in order.

  report_owner.py OWNER/NAME                 print the report (Markdown)
  report_owner.py OWNER/NAME --out FILE      save it to a file
  report_owner.py OWNER/NAME --issue         open it as an issue in that repository (asks you first, shows who can see it)
  report_owner.py OWNER/NAME --json          machine-readable: {repo, public, findings, report, link}

The report holds nothing about your computer: no folder names, no user name, no account details.
Exit code: 0 report written, 1 nothing found to report, 3 could not do it.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kitlib import safe_output  # noqa: E402
import github_check as gc  # noqa: E402

WHERE_RE = re.compile(r"^(?P<repo>[^ ]+) \((?P<branch>.+?)(?:, shared with you)?\)$")
MAX_ROWS = 40


def group(findings):
    """Findings of the repository scan as [(branch, severity, path, detail)], worst first, one row per file and reason."""
    rows, seen = [], set()
    for sev, where, detail in findings:
        m = WHERE_RE.match(str(where))
        branch = m.group("branch") if m else "-"
        path, _, why = str(detail).partition(" - ")
        key = (branch, path, why)
        if key in seen:
            continue
        seen.add(key)
        rows.append((branch, sev, path if why else "", why or path))
    rows.sort(key=lambda r: (r[1] != "DANGER", r[0], r[2]))
    return rows


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")[:200]


def build_report(repo, findings, public=False, tool_link="https://github.com/Abdul-Moiz31/ardvane"):
    """The Markdown report. `findings` are github_check findings for this repository."""
    rows = group(findings)
    danger = [r for r in rows if r[1] == "DANGER"]
    branches = sorted({r[0] for r in rows})
    lines = [f"# Malware found in {repo}", ""]
    lines += [f"A scan of **{repo}** found {len(danger)} serious and {len(rows) - len(danger)} lesser signs of malware"
              f" across {len(branches)} branch{'es' if len(branches) != 1 else ''}. "
              "Nothing was cloned or run: the files were only read.", "",
              "This kind of malware (for example PolinRider, from the \"Contagious Interview\" campaigns) runs when a project is "
              "opened in an editor or installed, steals tokens and keys, and then pushes itself into every repository the stolen "
              "access can reach. If you or a teammate cloned or opened this repository, treat that computer as exposed.", ""]
    lines += ["## What was found", "", "| Branch | Where | What |", "|---|---|---|"]
    for branch, sev, path, why in rows[:MAX_ROWS]:
        lines.append(f"| {cell(branch)} | {'`' + cell(path) + '`' if path else '-'} | {'**Serious.** ' if sev == 'DANGER' else ''}{cell(why)} |")
    if len(rows) > MAX_ROWS:
        lines.append(f"\n…and {len(rows) - MAX_ROWS} more.")
    lines += ["", "## What to do, in this order", "",
              "1. **Don't open the repository in an editor and don't run `npm install`** on a computer you care about until it is clean.",
              "2. **Cut off access first.** Revoke GitHub tokens and sign out other sessions (github.com/settings/tokens, github.com/settings/sessions), "
              "and rotate any key or secret that was on a computer that opened this repository.",
              "3. **Check who can push.** Remove collaborators, deploy keys and webhooks you don't recognise (repository Settings).",
              "4. **Block force pushes** on the default branch with a ruleset (Settings → Rules), so a stolen token can't rewrite history.",
              "5. **Remove the malware from every branch and tag**, not just the default branch. Deleting the file in a new commit leaves it in the "
              "history, where it can be found and run again; the history has to be rewritten, then every collaborator re-clones.",
              "6. **Scan the computers** that cloned it, and the other repositories you can push to: the worm spreads through them.", ""]
    lines += ["## About this report", "",
              f"Found with [Ardvane]({tool_link}), a free, open-source scanner that runs only on the sender's computer. "
              "It can check a repository, a whole account and a computer, and can clean the history. "
              "The findings above are file contents that match known malware, listed so you can verify them yourself."]
    if public:
        lines += ["", "> This repository is public, so anyone can read this report if it is posted as an issue. Prefer sending it privately "
                  "(a message, or GitHub's private vulnerability report: Security tab → Report a vulnerability, when enabled)."]
    return "\n".join(lines) + "\n"


def make(repo):
    """Scan one repository and build the report: {repo, public, findings, report, link, clean}."""
    name = gc.parse_repo(repo)
    login = gc.gh_login()
    client = gc.Client(use_gh=bool(login))
    info = client.get(f"/repos/{name}")
    name = info.get("full_name") or name
    res = gc.check("", 7, 15, True, True, [name])
    findings = [f for f in res["findings"] if str(f[1]).startswith(name + " (")]
    errors = [f for f in res["findings"] if f not in findings and f[0] == "WARNING" and f[1] == name]
    if errors and not findings:
        raise RuntimeError(errors[0][2])
    public = not info.get("private")
    return {"repo": name, "public": public, "findings": findings, "clean": not findings, "branches": res["branches_scanned"],
            "report": build_report(name, findings, public) if findings else "",
            "link": f"https://github.com/{name}/security/advisories/new" if public else "",
            "can_issue": bool(info.get("has_issues", True))}


def open_issue(repo, report):
    """Open the report as an issue in the repository, through gh. Returns the issue's address."""
    login = gc.gh_login()
    if not login or login == gc.CI_LOGIN:
        raise RuntimeError("log in with `gh auth login` first")
    client = gc.Client(use_gh=True)
    made = client.send("POST", f"/repos/{gc.parse_repo(repo)}/issues",
                       {"title": "Malware found in this repository", "body": report})
    return made.get("html_url", "") if isinstance(made, dict) else ""


def main(argv):
    safe_output()
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 3
    flags = {a for a in argv if a.startswith("--") and a != "--out"}
    out, args, it = None, [], iter(argv)
    for a in it:
        if a == "--out":
            out = next(it, None)
        elif not a.startswith("--"):
            args.append(a)
    if len(args) != 1 or ("--out" in argv and not out):
        print("report_owner: give exactly one repository (owner/name)", file=sys.stderr)
        return 3
    as_json = "--json" in flags
    try:
        data = make(args[0])
    except (RuntimeError, ValueError) as e:
        print(json.dumps({"error": str(e)}) if as_json else f"report_owner: {e}", file=sys.stdout if as_json else sys.stderr)
        return 3
    if as_json:
        print(json.dumps(data))
        return 0 if data["findings"] else 1
    if data["clean"]:
        print(f"Nothing to report: {data['repo']} has no signs of malware ({data['branches']} branches scanned).")
        return 1
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(data["report"])
        print(f"Report for {data['repo']} saved to {out}")
    elif "--issue" not in flags:
        print(data["report"])
    if "--issue" in flags:
        who = "ANYONE (the repository is public)" if data["public"] else "people who can read the repository"
        print(f"This will open an issue in {data['repo']}. Who can read it: {who}.")
        if input("Open it? Type the repository name to confirm: ").strip().lower() != data["repo"].lower():
            print("Not opened.")
            return 0
        try:
            print("Issue opened:", open_issue(data["repo"], data["report"]))
        except RuntimeError as e:
            print(f"report_owner: {e}", file=sys.stderr)
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
