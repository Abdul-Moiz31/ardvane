#!/usr/bin/env python3
"""Check your projects (and global npm packages) against the known-malicious package lists in this folder.

Read-only: it only reads package.json, lockfiles, requirements/pyproject, composer files and the names of
installed node_modules folders. Nothing is installed or executed.

Usage:
  python3 check-my-projects.py                    # scans ~/Documents ~/Desktop ~/Downloads ~/code ~/projects ~/source/repos
  python3 check-my-projects.py PATH [PATH ...]    # scan specific folders
Exit code: 0 nothing found, 1 at least one malicious package found.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    try:
        with open(os.path.join(HERE, name), encoding="utf-8") as f:
            return {l.strip() for l in f if l.strip() and not l.startswith("#")}
    except OSError:
        return set()


NPM, PYPI, PACKAGIST = load("npm.txt"), load("pypi.txt"), load("packagist.txt")
# "node_modules/<name>", "<name>":, <name>@<ver>, npm aliases "npm:<name>@", pnpm v6 keys "/<name>@" — never a longer name
NPM_RE = re.compile(r'(?:node_modules/|npm:|(?m:^)[ \t]*/|(?<![\w@/.-]))('
                    + "|".join(re.escape(n) for n in sorted(NPM, key=len, reverse=True)) + r')(?=["\'@:\s])') if NPM else None
NPM_FILES = ("package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock")
PY_FILES = ("requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock", "setup.py", "setup.cfg")
PHP_FILES = ("composer.json", "composer.lock")


def scan_file(path, name):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read(20_000_000)
    except OSError:
        return []
    hits = []
    if name in NPM_FILES and NPM_RE:
        hits += [("npm", m.group(1)) for m in NPM_RE.finditer(text)]
    if name in PY_FILES:
        hits += [("pypi", n) for n in PYPI if re.search(r'(?<![\w.-])' + re.escape(n) + r'(?![\w.-])', text, re.I)]
    if name in PHP_FILES:
        hits += [("packagist", n) for n in PACKAGIST if '"' + n + '"' in text]
    return hits


def main(argv):
    home = os.path.expanduser("~")
    given = [os.path.expanduser(a) for a in argv]
    for missing in [r for r in given if not os.path.isdir(r)]:
        print(f"⚠️  folder not found: {missing}")
    roots = given or [os.path.join(home, d) for d in ("Documents", "Desktop", "Downloads", "code", "projects", os.path.join("source", "repos"))]
    roots = [r for r in roots if os.path.isdir(r)]
    if not roots:
        print("Nothing was scanned — no existing folders given.")
        return 2
    found, files, nm_dirs = set(), 0, 0
    for root in roots:
        for dp, dns, fns in os.walk(root):
            if os.path.basename(dp) == "node_modules":
                nm_dirs += 1
                for d in dns:
                    try:
                        names = [d] if not d.startswith("@") else [d + "/" + x for x in os.listdir(os.path.join(dp, d)) if os.path.isdir(os.path.join(dp, d, x))]
                    except OSError:
                        names = []
                    for n in names:
                        if n in NPM:
                            found.add(("npm", n, os.path.join(dp, n), "INSTALLED"))
                # keep walking into scoped folders and each package, to reach nested node_modules/<pkg>/node_modules
                continue
            dns[:] = [d for d in dns if d not in (".git", ".venv", "venv", "__pycache__")]
            if "node_modules" in dp.split(os.sep):
                continue   # inside an installed package: only nested node_modules folders matter (handled above)
            for fn in fns:
                if fn in NPM_FILES or fn in PY_FILES or fn in PHP_FILES:
                    files += 1
                    for eco, n in scan_file(os.path.join(dp, fn), fn):
                        found.add((eco, n, os.path.join(dp, fn), "declared"))
    # globally installed npm packages
    try:
        groot = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True, timeout=20, shell=(os.name == "nt")).stdout.strip()
        if groot and os.path.isdir(groot):
            for d in os.listdir(groot):
                names = [d] if not d.startswith("@") else [d + "/" + x for x in os.listdir(os.path.join(groot, d))]
                for n in names:
                    if n in NPM:
                        found.add(("npm", n, os.path.join(groot, n), "GLOBAL INSTALL"))
    except Exception:
        pass
    print(f"Lists: {len(NPM)} npm, {len(PYPI)} PyPI, {len(PACKAGIST)} Packagist | checked {files} package files and {nm_dirs} node_modules folders in: {', '.join(roots)}")
    if not found:
        print("✅ None of the known-malicious packages are used or installed.")
        return 0
    print("🛑 Known-malicious packages found — do NOT run these projects. See ../6-after-a-scan/if-danger-found.md")
    for eco, n, where, how in sorted(found):
        print(f"  [{eco}] {n}  ({how})  {where.replace(home, '~')}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
