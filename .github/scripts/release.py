#!/usr/bin/env python3
"""Publish a GitHub release for the version in app/backend/config.py, once.

    python3 .github/scripts/release.py --check     verify the version has release notes in CHANGELOG.md (CI, every PR)
    python3 .github/scripts/release.py --version   print the version (used by the PyPI job)
    python3 .github/scripts/release.py             create tag + release v<version> unless it exists (release workflow)

To release: in a pull request, raise VERSION in app/backend/config.py and add a "## <version>" section to CHANGELOG.md.
When it is merged and the tests pass on main, the release workflow runs this script. Needs GH_TOKEN and SHA (the
commit to tag) in the environment; uses the GitHub CLI that GitHub's runners include.

Refuses to release a version older than the latest release, and refuses a tag that already exists on another commit
(a tag pushed by hand must never become the release). Tells the workflow (GITHUB_OUTPUT) the version, the commit the
release belongs to, and whether its signed source archive still has to be attached.
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONFIG = os.path.join(ROOT, "app", "backend", "config.py")
CHANGELOG = os.path.join(ROOT, "CHANGELOG.md")
PRODUCT = "Ardvane"


def version():
    with open(CONFIG, encoding="utf-8") as f:
        m = re.search(r'^VERSION = "(\d+\.\d+\.\d+)"$', f.read(), re.M)
    if not m:
        sys.exit(f"no VERSION = \"x.y.z\" line in {CONFIG}")
    return m.group(1)


def notes(ver):
    """The text under '## <ver>' in CHANGELOG.md, up to the next '## ' heading."""
    try:
        with open(CHANGELOG, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        sys.exit("CHANGELOG.md is missing")
    m = re.search(rf"^## {re.escape(ver)}\b[^\n]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    body = m.group(1).strip() if m else ""
    if not body:
        sys.exit(f"CHANGELOG.md has no notes for {ver}: add a '## {ver}' section")
    return body


def gh(*args):
    return subprocess.run(["gh", *args], capture_output=True, text=True)


def as_tuple(ver):
    return tuple(int(x) for x in ver.split("."))


def archive_name(ver):
    return f"ardvane-{ver}.tar.gz"


def output(**values):
    """Hand values to the following workflow steps."""
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.writelines(f"{k}={v}\n" for k, v in values.items())


def main(argv):
    ver = version()
    if "--version" in argv:
        print(ver)
        return 0
    body = notes(ver)
    if "--check" in argv:
        print(f"{PRODUCT} {ver}: release notes found ({len(body.splitlines())} lines)")
        return 0
    tag, sha = f"v{ver}", os.environ.get("SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        sys.exit("SHA must be the full commit hash to tag")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    existing = gh("release", "view", tag, "--json", "assets", "--jq", ".assets[].name")
    if existing.returncode == 0:
        commit = gh("api", f"repos/{repo}/commits/{tag}", "--jq", ".sha").stdout.strip()
        print(f"{tag} is already released (commit {commit[:12]})")
        output(version=ver, commit=commit, needs_archive=str(archive_name(ver) not in existing.stdout.split()).lower())
        return 0
    latest = gh("release", "view", "--json", "tagName", "--jq", ".tagName").stdout.strip().lstrip("v")
    if re.fullmatch(r"\d+\.\d+\.\d+", latest) and as_tuple(ver) < as_tuple(latest):
        sys.exit(f"refusing to release {ver}: it is older than the latest release {latest}")
    tagged = gh("api", f"repos/{repo}/commits/{tag}", "--jq", ".sha")
    if tagged.returncode == 0 and tagged.stdout.strip() != sha:
        sys.exit(f"tag {tag} already exists on commit {tagged.stdout.strip()[:12]}, not on the tested commit {sha[:12]}: "
                 "delete that tag (nobody should push release tags by hand) and run the workflow again")
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as f:
        f.write(body + "\n")
    r = gh("release", "create", tag, "--target", sha, "--title", f"{PRODUCT} {ver}", "--notes-file", f.name, "--latest")
    print(r.stdout.strip() or r.stderr.strip())
    if r.returncode == 0:
        output(version=ver, commit=sha, needs_archive="true")
    return r.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
