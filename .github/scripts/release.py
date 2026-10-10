#!/usr/bin/env python3
"""Publish a GitHub release for the version in app/backend/config.py, once.

    python3 .github/scripts/release.py --check     verify the version has release notes in CHANGELOG.md (CI, every PR)
    python3 .github/scripts/release.py --version   print the version (used by the PyPI job)
    python3 .github/scripts/release.py             create tag + release v<version> unless it exists (release workflow)

To release: in a pull request, raise VERSION in app/backend/config.py and add a "## <version>" section to CHANGELOG.md.
When it is merged and the tests pass on main, the release workflow runs this script. Needs GH_TOKEN and SHA (the
commit to tag) in the environment; uses the GitHub CLI that GitHub's runners include.
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
    if gh("release", "view", tag).returncode == 0:
        print(f"{tag} is already released — nothing to do")
        return 0
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as f:
        f.write(body + "\n")
    r = gh("release", "create", tag, "--target", sha, "--title", f"{PRODUCT} {ver}", "--notes-file", f.name, "--latest")
    print(r.stdout.strip() or r.stderr.strip())
    return r.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
