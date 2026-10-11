#!/usr/bin/env python3
"""safeinstall — check packages for known malware before npm / npx / pnpm / yarn / bun / pip install them.

Part of Ardvane (MIT License). Python 3.8+, no dependencies.

  safeinstall.py TOOL ARGS...     check what `TOOL ARGS...` would install. Exit 0: go ahead. Exit 10: blocked.

The shell functions Ardvane adds (scanner/safeinstall/functions.sh) call this before the real command and run the
command only if it doesn't say "blocked", so `npm install x` just works - unless x is known malware.

What is checked:
  - npm install / ci / update, npm exec / npx: the packages you name and every package in the lockfile. When npm is
    told to add packages, the full dependency tree is worked out first in a private temporary copy of the project
    (`npm install --package-lock-only --ignore-scripts`: downloads package metadata only, runs nothing, and changes
    none of your files).
  - pnpm / yarn / bun: the packages you name and every package in the lockfile.
  - pip / pip3 install: the packages you name and those in -r requirement files. (Not their dependencies: working
    those out can run code from the packages.)
Against:
  - Ardvane's own lists (built in, plus the signed detection feed): offline.
  - OSV.dev's database of malicious packages (MAL- advisories; it includes the OpenSSF malicious-packages list),
    unless turned off in Settings. Only public package names and versions are sent - never packages from a private
    registry - and answers are cached for a day.
If a package is known malware, nothing is installed. If OSV.dev can't be reached, the offline lists are used and you
are told. If this script itself fails, the install goes ahead with a warning: it never breaks your package manager.

Bypass once, only if you are sure:  command npm install ...   (PowerShell: npm.cmd install ...)
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kitlib import DEST, read_json, safe_output, setting, write_json   # noqa: E402
# checkrepo (built-in package lists + the detection feed) is imported only when a command installs something, so
# everyday commands like `npm run dev` pass through without delay.

BLOCKED = 10                     # anything else means "go ahead": a failure here must never block an install
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
OSV_CHUNK, OSV_TIMEOUT = 1000, 15
CACHE = os.path.join(DEST, "osv-cache.json")
CACHE_TTL, CACHE_MAX = 24 * 3600, 50000
PUBLIC_NPM = ("https://registry.npmjs.org/", "https://registry.yarnpkg.com/")
RESOLVE_TIMEOUT = 180

# subcommands that install packages, per tool ("" = the tool run with no subcommand, e.g. plain `yarn`)
INSTALLS = {
    "npm": {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "add", "ci",
            "clean-install", "install-clean", "update", "up", "upgrade", "install-test", "it", "exec", "x"},
    "pnpm": {"install", "i", "add", "update", "up", "upgrade", "dlx"},
    "yarn": {"", "install", "add", "up", "upgrade", "dlx"},
    "bun": {"install", "i", "add", "a", "update", "x"},
    "pip": {"install"}, "pip3": {"install"},
    "npx": None, "bunx": None,                     # these always run a package
}
# options that take a value, per tool (the value is not a package name). They differ: `-r` is a file for pip but means
# "recursive" for pnpm, and `-w` takes a workspace name in npm but none in pnpm.
_NPM_VALUES = {"--prefix", "--registry", "-w", "--workspace", "--tag", "--omit", "--include", "--cache", "--userconfig",
               "-p", "--package", "-c", "--call", "--shell"}
VALUE_FLAGS = {
    "npm": _NPM_VALUES, "npx": _NPM_VALUES,
    "pnpm": {"-C", "--dir", "-F", "--filter", "--registry", "--store-dir", "--reporter"},
    "yarn": {"--cwd", "--registry", "--modules-folder", "--cache-folder"},
    "bun": {"--cwd", "--registry", "-c", "--config", "--backend", "--cache-dir"},
    "pip": {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url",
            "-f", "--find-links", "-t", "--target", "--python", "--platform", "--root", "--prefix", "--src", "--report",
            "--upgrade-strategy", "--cache-dir", "--trusted-host", "--proxy", "--cert", "--client-cert", "--log",
            "--config-settings", "--global-option", "--progress-bar", "--python-version", "--implementation", "--abi"},
}
NPM_SPEC_RE = re.compile(r"^(?:[\w.~-]+@npm:)?((?:@[a-z0-9][\w.~-]*/)?[a-z0-9][\w.~-]*)(?:@(.*))?$", re.I)
EXACT_RE = re.compile(r"^v?(\d+\.\d+\.\d+(?:[-+][\w.+-]*)?)$")
PIP_SPEC_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:==\s*([\w.!+-]+))?")


class Pkg:
    """One package that would be installed: ecosystem ("npm" | "PyPI"), name, exact version or None."""
    __slots__ = ("eco", "name", "version", "public")

    def __init__(self, eco, name, version=None, public=True):
        self.eco, self.name, self.version, self.public = eco, name, version, public

    def key(self):
        return f"{self.eco}:{self.name}@{self.version or ''}"

    def label(self):
        return f"{self.name}@{self.version}" if self.version else self.name


def pep503(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def subcommand(tool, args):
    """(subcommand, the arguments after it). Option values before it are skipped: in `pnpm -C web add x` the
    subcommand is `add`, not the folder `web`."""
    values = VALUE_FLAGS.get(tool.rstrip("3"), set())
    i = 0
    while i < len(args):
        if not args[i].startswith("-"):
            return args[i], args[i + 1:]
        i += 2 if args[i] in values else 1
    return "", []


def named(tool, args):
    """Words that are package specs: not options, not option values, not paths, URLs or git sources."""
    values = VALUE_FLAGS.get(tool, set())
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a.startswith("-"):
            skip = a in values
            continue
        if a.startswith((".", "/", "~", "file:", "git", "http:", "https:", "link:", "workspace:")) or "\\" in a:
            continue
        if "/" in a and not a.startswith("@"):                     # GitHub shorthand user/repo
            continue
        out.append(a)
    return out


def npm_spec(spec):
    m = NPM_SPEC_RE.match(spec.strip())
    if not m:
        return None
    exact = EXACT_RE.match(m.group(2) or "")
    return Pkg("npm", m.group(1).lower(), exact.group(1) if exact else None)


def pip_spec(spec):
    m = PIP_SPEC_RE.match(spec.strip())
    return Pkg("PyPI", pep503(m.group(1)), m.group(2)) if m else None


def requirement_files(args):
    """Files named with -r FILE, -rFILE or --requirement[=]FILE."""
    files = []
    for i, a in enumerate(args):
        if a in ("-r", "--requirement"):
            files += args[i + 1:i + 2]
        elif a.startswith("--requirement="):
            files.append(a.split("=", 1)[1])
        elif a.startswith("-r") and not a.startswith("--"):
            files.append(a[2:])
    return files


def read_requirements(path, depth=0):
    pkgs = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return pkgs
    for line in lines:
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ")) and depth < 5:
            pkgs += read_requirements(os.path.join(os.path.dirname(path), line.split(None, 1)[1]), depth + 1)
        elif not line.startswith("-"):
            p = pip_spec(line)
            if p:
                pkgs.append(p)
    return pkgs


# ---------------------------------------------------------------- lockfiles
def npm_lock(path):
    """Packages in package-lock.json / npm-shrinkwrap.json (v1, v2 and v3), with versions and where they come from."""
    data = read_json(path, {})
    pkgs = []
    for key, info in (data.get("packages") or {}).items():
        if key and isinstance(info, dict) and "node_modules/" in key and not info.get("link"):
            name = info.get("name") or key.rsplit("node_modules/", 1)[1]
            resolved = str(info.get("resolved") or "")
            pkgs.append(Pkg("npm", name.lower(), info.get("version"), resolved.startswith(PUBLIC_NPM) or not resolved))
    stack = [data.get("dependencies") or {}] if not pkgs else []
    while stack:                                                   # lockfile v1: nested "dependencies"
        for name, info in stack.pop().items():
            if isinstance(info, dict):
                resolved = str(info.get("resolved") or "")
                pkgs.append(Pkg("npm", name.lower(), info.get("version"), resolved.startswith(PUBLIC_NPM) or not resolved))
                if isinstance(info.get("dependencies"), dict):
                    stack.append(info["dependencies"])
    return pkgs


LOCK_PAIR_RE = re.compile(r"""(?:^|[\s"'/(])((?:@[\w.~-]+/)?[\w.~-]+)@(?:npm:)?(\d+\.\d+\.\d+[\w.+-]*)""", re.M)
YARN_BLOCK_RE = re.compile(r'^"?((?:@[\w.~-]+/)?[\w.~-]+)@[^\n]*\n(?:[ \t]+[^\n]*\n)*?[ \t]+version:?\s+"?([\w.+-]+)"?', re.M)


def text_lock(path):
    """Packages in pnpm-lock.yaml, yarn.lock or bun.lock (name@exact-version pairs)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read(60_000_000)
    except OSError:
        return []
    pairs = YARN_BLOCK_RE.findall(text) if path.endswith("yarn.lock") else LOCK_PAIR_RE.findall(text)
    return [Pkg("npm", n.lower(), v) for n, v in pairs]


def lockfile_packages(folder):
    for name in ("package-lock.json", "npm-shrinkwrap.json"):
        p = os.path.join(folder, name)
        if os.path.isfile(p):
            return npm_lock(p)
    for name in ("pnpm-lock.yaml", "yarn.lock", "bun.lock"):
        p = os.path.join(folder, name)
        if os.path.isfile(p):
            return text_lock(p)
    return []


def resolve_npm(folder, specs, args):
    """The full tree npm would install for `specs`, worked out in a private copy of the project: lockfile only
    (metadata, no package code, no scripts). None if npm can't do it here (e.g. a workspace member)."""
    npm = shutil.which("npm")
    if not npm:
        return None
    tmp = tempfile.mkdtemp(prefix="ardvane-resolve-")
    try:
        for name in ("package.json", "package-lock.json", "npm-shrinkwrap.json", ".npmrc"):
            if os.path.isfile(os.path.join(folder, name)):
                shutil.copy2(os.path.join(folder, name), os.path.join(tmp, name))
        flags = [a for a in args if a.startswith("--") and a.split("=")[0] in ("--save-dev", "--save-optional", "--save-peer", "--legacy-peer-deps", "--force", "--registry")]
        env = dict(os.environ, npm_config_ignore_scripts="true", npm_config_audit="false", npm_config_fund="false",
                   npm_config_update_notifier="false")
        r = subprocess.run([npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", *flags, *specs],
                           cwd=tmp, env=env, capture_output=True, timeout=RESOLVE_TIMEOUT, stdin=subprocess.DEVNULL)
        lock = os.path.join(tmp, "package-lock.json")
        return npm_lock(lock) if r.returncode == 0 and os.path.isfile(lock) else None
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- what a command would install
def plan(tool, args, folder):
    """(packages, notes) for an install command, or None if `tool args` doesn't install anything."""
    base = "pip" if tool == "pip3" else ("npx" if tool == "bunx" else tool)
    if base not in INSTALLS and tool not in INSTALLS:
        return None
    if base == "npx":
        specs = [a.split("=", 1)[1] for a in args if a.startswith("--package=")]
        specs += [args[i + 1] for i, a in enumerate(args) if a in ("-p", "--package") and i + 1 < len(args)]
        specs = specs or named("npm", args)[:1]
        return [p for p in map(npm_spec, specs) if p], []
    sub, rest = subcommand(tool, args)
    if sub not in INSTALLS[tool]:
        return None
    notes = []
    if base == "pip":
        pkgs = [p for p in map(pip_spec, named("pip", rest)) if p]
        for f in requirement_files(rest):
            pkgs += read_requirements(os.path.join(folder, os.path.expanduser(f)))
        if pkgs:
            notes.append("pip: checked the packages you named; their own dependencies are checked by Ardvane's scans")
        return pkgs, notes
    if sub in ("exec", "x", "dlx"):                                 # npm exec / pnpm dlx / yarn dlx / bun x: run a package
        return [p for p in map(npm_spec, named(base, rest)[:1]) if p], notes
    specs = named(base, rest)
    pkgs = [p for p in map(npm_spec, specs) if p]
    tree = resolve_npm(folder, specs, rest) if tool == "npm" and specs else None
    if tree is not None:
        pkgs += tree
    else:
        pkgs += lockfile_packages(folder)
        if specs and tool != "npm":
            notes.append(f"{tool}: checked the packages you named and your lockfile; new dependencies are checked by Ardvane's scans")
    return pkgs, notes


# ---------------------------------------------------------------- checks
def private_scopes(folder):
    """npm scopes served by another registry (.npmrc "@scope:registry=..."): never sent to OSV.dev."""
    scopes = set()
    for rc in (os.path.join(folder, ".npmrc"), os.path.expanduser("~/.npmrc")):
        try:
            with open(rc, encoding="utf-8", errors="replace") as f:
                scopes |= {m.group(1).lower() for m in re.finditer(r"^\s*(@[\w.~-]+):registry\s*=", f.read(), re.M)}
        except OSError:
            pass
    return scopes


def custom_index(tool, args):
    """True if packages come from a registry other than the public one (then names are never sent to OSV.dev)."""
    if tool in ("pip", "pip3"):
        return any(a.startswith(("-i", "--index-url", "--extra-index-url")) for a in args) or bool(os.environ.get("PIP_INDEX_URL"))
    reg = os.environ.get("npm_config_registry") or os.environ.get("NPM_CONFIG_REGISTRY") or ""
    return bool(reg) and not reg.startswith(PUBLIC_NPM) or any(a.startswith("--registry") for a in args)


def local_hits(pkgs):
    import checkrepo
    npm, pypi = checkrepo.MALICIOUS_NPM, checkrepo.MALICIOUS_PYPI
    return [(p, "Ardvane's list of known malicious packages") for p in pkgs
            if (p.eco == "npm" and p.name in npm) or (p.eco == "PyPI" and p.name in pypi)]


def http_json(url, body=None, timeout=OSV_TIMEOUT):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": "ardvane-safeinstall"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(20_000_000).decode("utf-8"))


def whole_package(advisory_id, cache):
    """True if a MAL advisory covers every version (a fake package), False if only some versions were malicious."""
    if advisory_id in cache.get("advisories", {}):
        return cache["advisories"][advisory_id]
    try:
        vuln = http_json(OSV_VULN + advisory_id)
    except Exception:
        return True
    whole = all(not a.get("versions") and all(e.get("introduced") == "0" and len(r.get("events", [])) == 1
                                              for r in a.get("ranges", []) for e in r.get("events", []))
                for a in vuln.get("affected", []))
    cache.setdefault("advisories", {})[advisory_id] = whole
    return whole


def osv_hits(pkgs, cache):
    """[(pkg, reason)] for packages OSV.dev knows as malicious, and warnings for ones where only some versions were.
    Raises OSError / ValueError when OSV.dev can't be reached."""
    now = time.time()
    entries = cache.setdefault("packages", {})
    todo = [p for p in pkgs if not (p.key() in entries and now - entries[p.key()][0] < CACHE_TTL)]
    for i in range(0, len(todo), OSV_CHUNK):
        chunk = todo[i:i + OSV_CHUNK]
        queries = [dict({"package": {"name": p.name, "ecosystem": p.eco}}, **({"version": p.version} if p.version else {}))
                   for p in chunk]
        results = http_json(OSV_BATCH, {"queries": queries}).get("results", [])
        for p, res in zip(chunk, results):
            entries[p.key()] = [now, [v["id"] for v in res.get("vulns", []) if v.get("id", "").startswith("MAL-")]]
    blocked, warned = [], []
    for p in pkgs:
        for mal in entries.get(p.key(), [0, []])[1]:
            if p.version or whole_package(mal, cache):
                blocked.append((p, f"{mal}  https://osv.dev/vulnerability/{mal}"))
            else:
                warned.append((p, f"some versions were malicious ({mal}): make sure you get a safe one"))
    return blocked, warned


def load_cache():
    cache = read_json(CACHE, {})
    if len(cache.get("packages", {})) > CACHE_MAX:
        cache = {}
    return cache


def check(tool, args, folder=None, use_osv=None):
    """(blocked, warned, notes, count) for `tool args` run in `folder`; None if the command installs nothing."""
    folder = folder or os.getcwd()
    p = plan(tool, args, folder)
    if p is None:
        return None
    pkgs, notes = p
    unique = list({x.key(): x for x in pkgs}.values())
    blocked, warned = local_hits(unique), []
    use_osv = setting("package_lookups", True) is not False if use_osv is None else use_osv
    if use_osv and unique:
        scopes = private_scopes(folder)
        public = [x for x in unique if x.public and not (x.name.startswith("@") and x.name.split("/")[0] in scopes)]
        if custom_index(tool, args):
            public = []
            notes.append("a private registry is in use, so package names were checked offline only")
        if public:
            cache = load_cache()
            try:
                b, w = osv_hits(public, cache)
                blocked += [x for x in b if x[0].key() not in {y[0].key() for y in blocked}]
                warned += w
                write_json(CACHE, cache)
            except Exception as e:
                notes.append(f"OSV.dev couldn't be reached ({e.__class__.__name__}), so only Ardvane's own list was checked")
    return blocked, warned, notes, len({(x.eco, x.name) for x in unique})


def by_package(findings):
    """{(ecosystem, name): [reasons]} - one row per package, however many versions or sources flagged it."""
    rows = {}
    for p, why in findings:
        whys = rows.setdefault((p.eco, p.name), [])
        if why not in whys:
            whys.append(why)
    return rows


def main(argv):
    safe_output()
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    tool, args = os.path.basename(argv[0]).lower(), argv[1:]
    try:
        result = check(tool, args)
    except Exception as e:                       # never break the user's package manager
        print(f"Ardvane: the package check failed ({e.__class__.__name__}: {e}) - installing without it", file=sys.stderr)
        return 0
    if result is None:
        return 0
    blocked, warned, notes, count = result
    tty = sys.stderr.isatty()
    R, Y, D, X = ("\033[1;31m", "\033[1;33m", "\033[2m", "\033[0m") if tty else ("",) * 4
    rows = by_package(blocked)
    for (eco, name), whys in by_package(warned).items():
        if (eco, name) not in rows:                       # a blocked package needs no "some versions" warning too
            print(f"{Y}⚠️  Ardvane: {name}: {'; '.join(whys)}{X}", file=sys.stderr)
    for n in notes:
        print(f"{D}Ardvane: {n}{X}", file=sys.stderr)
    if rows:
        print(f"\n{R}🛑 Ardvane blocked this install: known malicious package{'s' if len(rows) > 1 else ''}. Nothing was installed.{X}", file=sys.stderr)
        for (eco, name), whys in rows.items():
            print(f"   {eco:4}  {name:36}  {whys[0]}", file=sys.stderr)
            for why in whys[1:]:
                print(f"   {'':4}  {'':36}  {why}", file=sys.stderr)
        print(f"   If you are 100% sure this is a false alarm:  command {tool} {' '.join(args)}\n", file=sys.stderr)
        return BLOCKED
    if count:
        print(f"{D}Ardvane: checked {count} package{'s' if count != 1 else ''} - no known malware{X}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
