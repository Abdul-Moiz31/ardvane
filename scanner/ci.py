#!/usr/bin/env python3
"""ci — Ardvane in GitHub Actions (run by action.yml at the root of the repository).

Part of Ardvane (MIT License). Python 3.8+, no dependencies. Read-only: nothing from a scanned repository is run.

Modes (input `mode`):
  checkout       scan the checked-out code (every push and pull request). Findings appear on the files in the pull
                 request and in the job summary.
  all-branches   scan every branch of this repository, and of any repositories listed in `repositories`, through the
                 GitHub API - no checkout needed. Run it on a schedule: branches nobody opens locally (dependabot,
                 old feature branches) are where the worm hides.
The job fails on `fail-on`: danger (default), warning, or never.

Configured through environment variables set by action.yml (never interpolated into a shell command):
  ARDVANE_MODE, ARDVANE_FAIL_ON, ARDVANE_REPOS (one per line), ARDVANE_UPDATE ("true": fetch the signed detection
  list first), ARDVANE_PATH (folder to scan in checkout mode, default the workspace), GH_TOKEN.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

MODES = ("checkout", "all-branches")
FAIL_ON = ("danger", "warning", "never")
WHAT_TO_DO = "https://github.com/Abdul-Moiz31/ardvane/blob/main/docs/after-a-scan/if-danger-found.md"


def escape(value, prop=False):
    """GitHub workflow-command escaping. Findings carry file names from the scanned repository: unescaped, a file
    named like `x\\n::add-mask::...` could inject commands into the workflow."""
    value = str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return value.replace(":", "%3A").replace(",", "%2C") if prop else value


def annotation(level, message, title, file=None):
    props = ",".join(f"{k}={escape(v, prop=True)}" for k, v in (("file", file), ("title", title)) if v)
    return f"::{level} {props}::{escape(message)}"


def md(value):
    """Text for a Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;")


def scan_checkout(path):
    """[(severity, where, file, detail)] for the checked-out code."""
    import checkrepo
    s = checkrepo.Scan(path)
    s.walk()
    return [(sev, rel, rel, detail) for sev, _rule, rel, detail in s.findings]


def scan_branches(repos):
    """[(severity, where, file, detail)] and notes for every branch of `repos`, through the GitHub API."""
    import github_check
    res = github_check.check("", rescan=True, repos=repos)
    rows = [(sev, where, None, detail) for sev, where, detail in res["findings"]]
    notes = [f"{r['repo']}: {r['outcome']}" + (f" ({r['branches']} branches)" if r.get("branches") else "") for r in res["listed"]]
    return rows, notes + res["notes"]


def update_detections():
    import feed
    try:
        state, f = feed.update()
        return f"Detections: {feed.summary(f)}" + (" (updated)" if state == "updated" else "")
    except feed.FeedError as e:
        return f"Detections: built-in only - the detection list couldn't be updated ({e})"


def summary(rows, notes, mode, target):
    danger = sum(1 for r in rows if r[0] == "DANGER")
    warn = len(rows) - danger
    head = ("🛑 **Malware found**" if danger else "⚠️ **No malware, but some things are worth a look**" if warn
            else "✅ **No signs of malware**")
    lines = [f"## Ardvane malware scan", "", f"{head} - {target} ({'every branch' if mode == 'all-branches' else 'checked-out code'})", ""]
    if rows:
        lines += ["| | Where | What |", "|---|---|---|"]
        lines += [f"| {'🛑' if sev == 'DANGER' else '⚠️'} | `{md(where)}` | {md(detail)} |" for sev, where, _f, detail in rows]
        lines.append("")
    if danger:
        lines += [f"**Don't open these files or run `npm install` here.** What to do: [cut off access first, then clean]({WHAT_TO_DO}).", ""]
    lines += [f"- {md(n)}" for n in notes]
    lines += ["", "_Read-only: nothing from the repository was run. [Ardvane](https://github.com/Abdul-Moiz31/ardvane)_"]
    return "\n".join(lines) + "\n", danger, warn


def append(path_var, text):
    path = os.environ.get(path_var)
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    mode = os.environ.get("ARDVANE_MODE", "checkout").strip() or "checkout"
    fail_on = os.environ.get("ARDVANE_FAIL_ON", "danger").strip() or "danger"
    if mode not in MODES or fail_on not in FAIL_ON:
        print(f"::error title=Ardvane::mode must be one of {', '.join(MODES)} and fail-on one of {', '.join(FAIL_ON)}")
        return 2
    notes = [update_detections()] if os.environ.get("ARDVANE_UPDATE", "true").strip().lower() == "true" else []
    if mode == "checkout":
        path = os.environ.get("ARDVANE_PATH") or os.environ.get("GITHUB_WORKSPACE") or os.getcwd()
        if not os.path.isdir(path):
            print(f"::error title=Ardvane::{escape(path)} is not a folder - check out the repository first (actions/checkout)")
            return 2
        rows, target = scan_checkout(path), os.environ.get("GITHUB_REPOSITORY", path)
    else:
        import github_check
        repos = []
        for line in [os.environ.get("GITHUB_REPOSITORY", "")] + os.environ.get("ARDVANE_REPOS", "").splitlines():
            if line.strip():
                try:
                    name = github_check.parse_repo(line)
                except ValueError as e:
                    print(annotation("error", str(e), "Ardvane: repositories"))
                    return 2
                if name.lower() not in {r.lower() for r in repos}:
                    repos.append(name)
        if not repos:
            print("::error title=Ardvane::no repository to scan (GITHUB_REPOSITORY is empty and `repositories` lists none)")
            return 2
        rows, more = scan_branches(repos)
        notes += more
        target = ", ".join(repos)
    for sev, where, file, detail in rows:
        print(annotation("error" if sev == "DANGER" else "warning", detail, f"Ardvane: {where}" if not file else "Ardvane", file))
    for n in notes:
        print(n)
    text, danger, warn = summary(rows, notes, mode, target)
    append("GITHUB_STEP_SUMMARY", text)
    append("GITHUB_OUTPUT", f"danger={danger}\nwarnings={warn}\n")
    print(f"Ardvane: {danger} serious finding(s), {warn} worth a look")
    if (danger and fail_on in ("danger", "warning")) or (warn and fail_on == "warning"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
