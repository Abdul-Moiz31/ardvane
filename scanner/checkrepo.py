#!/usr/bin/env python3
"""checkrepo — read-only scanner for PolinRider / Contagious Interview / TasksJacker / GlassWorm-style malware.

Part of polinrider-survival-kit (MIT License).

It NEVER executes anything from the scanned folder; it only reads bytes. Works on macOS, Linux and Windows
(Python 3.8+, no dependencies).

Severity:
  DANGER  — specific evidence of the campaign (blocks safe-clone and push when used with the git hooks)
  WARNING — unusual but can be legitimate (shown, never blocks)

Exit code: 0 clean, 1 danger found, 2 warnings only, 3 usage error.

Usage:
  checkrepo [folder]                 scan a folder (default: current folder)
  checkrepo --quiet [folder]         print only when something is found (used by git hooks)
  checkrepo --json [folder]          machine-readable output
  checkrepo --include-deps [folder]  also scan node_modules (slow; for deep audits)
  checkrepo --version | --help

In a git work tree it scans what the repository contains (tracked + new non-ignored files), so generated
build output that git ignores is skipped. Any other folder (e.g. an unzipped download) is scanned fully.

False alarm? Add the file's SHA-256 to ~/.config/checkrepo/allowlist (one per line). Allow-listing is by exact
content, so if the file ever changes it is scanned again.

Detection rules are modelled on real samples from the campaign plus the public research and community
detectors credited in the repository's README.
"""
VERSION = "1.0.0"
import hashlib
import json
import os
import re
import sys

# ---------------------------------------------------------------- indicators
# Exact SHA-256 of known payload files (certain match).
KNOWN_HASHES = {
    "ce20d9cfa23ac3a25ac41fa9d9da5935102996249934233df5d85c74551a647a",  # root api.js dropper
    "8b8ee2a11453ca691a51ccaa18de0c1f94d5237fddd7aaf425aceb550290d38c",  # babel.config.js blob
    "3b572a613f5013a64e1877dfed3873f2bcbd52e5259b199d41e02c33840abbcb",  # fa-solid-300.llf
    "7922bce938af965008c1481f5f47d6c85b09217e10147fa35979e8aa4585ff8d",  # jest.config.js
    "586e1904c8e8d69ab58e9e1c77fc5e7a044d910bb57b3f3b8d587368b4f84d15",  # fake fa-solid-900.woff2
    "d16f87b70496999cfbb907ff3a7693cdfea6db5ecd21d6faafbb8320530ff2a4",  # .vscode/tasks.json
    "92823600a82bdc05b1474176504f94e725068852764577f58c9529dedb7c35ed",  # .vscode/tasks.json variant
    "1abb6c799080b3641d88dc541d0eafbc5a8c153d05d482745191e8887a1debf5",  # .vscode/settings.json
    # MicrosoftSystem64 second-stage implant (Node single-executable) + dropper — JFrog / safedep, 2026
    "f2c754a7f7b56e0e2a6dd429f06c42a1860c52c37b25d0a8e91c67d1239fa577",
    "457a3323fe0cfa82d6e102074c6f07a399f55c7e0ce2d3b40643d9cfde0cf220",
    "2fec04f2985510654d9656d57f6817de1ca0d6ae49e7085b1e33abb38f89cc55",
    "b505f1d1ca3dca8cb7e2b2dd99991b5a929ec9387f3de31ad36549823af07dfd",
    "b2954c945b51dbd6fa88ac72338b7fbf76dec7d9909ceada9d36b21330842c97",
    "33401580619ae79bf3f87aab16208f169a44a038f18671b1def7836fb2682c9a",  # print.cjs dropper
}
KNOWN_HASHES_FILE = os.path.expanduser("~/.config/checkrepo/known_hashes")  # optional extra list (one sha256 per line)

# Campaign-specific markers: unambiguous, never found in legitimate code.
MARKER_RE = re.compile(
    r"""global\[\s*['"](?:!|_V|_H2?|_t_[a-z])['"]\s*\]\s*="""          # global['!']= / global['_V']= ...
    r"""|global\.i\s*=\s*['"][A-Z]\d{1,3}(?:-[\d*]{2,6}){0,2}['"]"""      # global.i = 'A11' / 'A10-*23650' (letter required)
    r"""|global\.o\s*=\s*['"]\d{1,3}-"""                                  # global.o='5-...
    r"""|_\$_(?:1e42|fed0)|rmcej%otb%|Cot%3t=shtP|\bfunction MDy\(|A10-npm3!"""
    r"""|aHR0cHM6Ly9hdXRoLWNvbi1maXJt|auth-con-firm"""
)
MARKER_STRINGS = [
    # XOR keys / template fingerprint
    "2[gWfGj;<:-93Z^C", "m6:tTh^D)cBz?NM]", "ThZG+0jfXE6VAGOJ", "e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9",
    # blockchain dead-drops
    "a322e5f3d311d3080e6f0121063e9adc2490ef1a", "0xE1f2395ee43e45A1556EC6438a88c31B83493103",
    "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP", "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG", "TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v",
    "0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e",
    "0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3",
    "0x533b2dbcaeff19cd1f799234a27b578d713d8fcaa341b7501e4526106483e0b1",
    # C2 / staging hosts
    "260120.vercel.app", "default-configuration.vercel.app", "vscode-settings-bootstrap.vercel.app",
    "vscode-settings-config.vercel.app", "vscode-bootstrapper.vercel.app", "vscode-load-config.vercel.app",
    "vscode-toolkit-bootstrap.vercel.app", "vscodesettingstask.vercel.app", "vscode-config-settings.vercel.app",
    "vscode-extension-260120.vercel.app", "regioncheck.xyz", "vscodeconfig.com", "vscode-load.onrender.com",
    # Telegram exfil bot token prefix
    "7870147428:AAG",
    # Oct 2026 additions (polinrider-cleaner weekly review, OpenSourceMalware, JFrog, safedep)
    "YU7m{rE/>|==b>#~", "q4FZkxX{!h,Sr3=@", "y-p_>d$0B&@^1aQk",
    "TCqf6ZkaQD84vYsC2cuu1jRwB6JveTaRrF", "TFMryB9m6d4kBMRjEVyFRbqKSV1cV2NcpH",
    "0x3d2075f97b7b1e3234bd653779d21c605d7d8c6ec9c98d983880be5c7f4f9471",
    "0x9d202c824402ca89e9aaccd2390b6f8b332ae743caa1469c695feb2781d56519",
    "Lordplay/system-releases", "jpeek998/system-releases", "copilot-ai.whisdev.org", "test26330331/test",
    "MicrosoftSystem64", "com.launchkeeper.", "SvcHostUpdate", "MicrosoftCLROptimization",
]
C2_IPS = ['136.0.9.8', '150.251.113.223', '154.91.0.103', '166.88.134.62', '166.88.134.75', '166.88.134.82', '166.88.4.2', '166.88.54.158', '166.88.73.46', '179.43.166.242', '181.214.149.147', '181.214.149.148', '188.43.33.249', '193.247.144.38', '195.201.194.107', '198.105.127.210', '202.155.8.173', '23.27.120.142', '23.27.13.135', '23.27.13.43', '23.27.20.187', '23.27.202.27', '45.137.198.133', '91.218.183.174']
# All known-bad package names in one pass: "node_modules/<name>", "<name>":, <name>@<ver> — never part of another name
BAD_PKG_RE = None  # built after MALICIOUS_NPM below

# IPs only count when they stand alone (not part of a version number like 1.136.0.9.8)
C2_IP_RE = re.compile(r"(?<![\d.])(?:" + "|".join(re.escape(i) for i in C2_IPS) + r")(?![\d.])")

MALICIOUS_NPM = {
    "@hoteldev/common", "@nasddatax/common", "@nasdtickets/common", "@rentwise/common", "@simplipayng/checkout", "@uw010010/vite-tree",
    "@vboxdev/common", "@vite-ln/build-ts", "@vite-mcp/vite-type", "@vite-pro/vite-ui", "@vite-tab/tab", "@vite-ts/vite-ui",
    "@vitets/vite-ts", "@wizloft/harness", "@wizloft/harness-context", "@wizloft/harness-kernel", "@wizloft/harness-plugin-repository-files", "@wizloft/harness-validation",
    "@zahlen/checkout-angular", "@zahlen/checkout-react", "anhn-cli", "bianira-ui", "changelog-logger-utilities", "devpack-conf",
    "envpack-conf", "fluid-type-ui", "iconova-react", "js-logger-pack", "jsonwebauth", "node-env-resolve",
    "pinno-loggers", "polymarket-validator", "post-css-transfer", "postcss-initial-provider", "postcss-initialize-plugin", "postcss-theme-provider",
    "pretty-logger-utils", "pybitjs", "pyservercheck", "rate-limit-flexible", "rate-limits-flexible", "react-scroll-disable",
    "sass-formats", "scrollbar-hide-plugin", "simplipayng", "tailwind-animate-plugin", "tailwind-animationbased", "tailwind-animationgroup",
    "tailwind-animationpack", "tailwind-anime", "tailwind-autoanimation", "tailwind-contact-forms", "tailwind-custom-forms", "tailwind-custom-templates",
    "tailwind-form-styles", "tailwind-form-templates", "tailwind-forms-kit", "tailwind-forms-styles", "tailwind-hide-scrollbar", "tailwind-mainanimation",
    "tailwind-minanimated", "tailwind-modernanimation", "tailwind-opentype", "tailwind-scrollbar-styles", "tailwindcss-3d-animate", "tailwindcss-animate-style",
    "tailwindcss-animate-styles", "tailwindcss-animates-kit", "tailwindcss-animatics", "tailwindcss-contact-form", "tailwindcss-contact-forms", "tailwindcss-fluid-styles",
    "tailwindcss-form-ui", "tailwindcss-form-utils", "tailwindcss-forms-style", "tailwindcss-forms-styles", "tailwindcss-forms-ui", "tailwindcss-merge",
    "tailwindcss-motion-advanced", "tailwindcss-scrollbar-hide", "tailwindcss-style-animate", "tailwindcss-style-modify", "tailwindcss-typography-style", "terminal-logger-utils",
    "ts-logger-pack", "uibabai",
}

# Matches "node_modules/<name>", "<name>":, <name>@<ver>, npm aliases "npm:<name>@", pnpm v6 keys "/<name>@" —
# never a longer name that merely contains <name> (e.g. "@acme/<name>" or "<name>-extra").
BAD_PKG_RE = re.compile(r'(?:node_modules/|npm:|(?m:^)[ \t]*/|(?<![\w@/.-]))('
                        + "|".join(re.escape(n) for n in sorted(MALICIOUS_NPM, key=len, reverse=True)) + r')(?=["\'@:\s])')

# ---------------------------------------------------------------- file classes
SKIP_DIRS = {".git", "node_modules", "bower_components", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache"}
CODE_EXT = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx")
FONT_EXT = (".woff", ".woff2", ".ttf", ".otf", ".eot", ".llf", ".fnt")
MAX_READ = 5 * 1024 * 1024
MAX_READ_LOCKFILE = 50 * 1024 * 1024   # monorepo lockfiles are often 5-20 MB

# Payload appended after a long run of whitespace: real samples use 149–776 spaces then 25–40 KB of code.
HIDDEN_RE = re.compile(r"\S([ \t]{60,})(\S[^\n]{300,})")
# The payload begins immediately after the whitespace with one of the campaign's loader openings.
HIDDEN_CODE_RE = re.compile(r"(?:global\[\s*['\"]|global\.[A-Za-z_]\w*\s*=\s*['\"]|(?:var|let|const)\s+_0x[0-9a-f]{4}|function\s+_0x[0-9a-f]{4}|\(function\s*\(\s*_0x[0-9a-f]{4}|eval\(\s*(?:atob|Buffer\.from|String\.fromCharCode))")

JS_LIKE_RE = re.compile(r"global\[|global\.[A-Za-z_]+\s*=|_0x[0-9a-f]{4}|\brequire\(|\bfunction\b")
FOLDER_OPEN_RE = re.compile(r'"runOn"\s*:\s*"folderOpen"')
# A command that runs a disguised payload or a downloaded script. Applied to individual commands (auto-run tasks,
# AI-agent hooks / MCP servers), never to whole files, so unrelated URLs elsewhere in a file can't trigger it.
# Known C2 hosts (e.g. the *.vercel.app loaders) are matched exactly by MARKER_STRINGS instead.
TASK_LOADER_RE = re.compile(
    r"node\s+(?:-\S+\s+)*[^&|;\"]*?\.(?:woff2?|llf|eot|ttf|otf|fnt|dict)\b|node\s+(?:-\S+\s+)*[^&|;\"]*?/fonts/"
    r"|command -v node[^\"]*\|\|\s*\(?\s*where node\s*>\s*nul"
    r"|\b(?:curl|wget)\b[^\"]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|cmd)\b"
    r"|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\"]*\|\s*(?:iex|invoke-expression)\b", re.I)
HIDDEN_TASK_RE = re.compile(r'"hide"\s*:\s*true|"reveal"\s*:\s*"never"')
AUTO_TASKS_RE = re.compile(r'"task\.allowAutomaticTasks"\s*:\s*(?:"on"|true)')
TRUST_OFF_RE = re.compile(r'"security\.workspace\.trust\.enabled"\s*:\s*false')
CODE_AUX_RE = re.compile(r"\brequire\s*\(|\bfunction\b|=>|\bprocess\.|child_process|Buffer\.from|\bglobal\[")
HEXRUN_RE = re.compile(r"[0-9a-fA-F]{200,}")

LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish")
LIFECYCLE_DANGER_RE = re.compile(
    r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|node|python3?)\b"
    r"|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b.*\|\s*(?:iex|invoke-expression)\b"
    r"|\bbase64\s+(?:-d|--decode)\b.*\|\s*(?:sh|bash|zsh|dash)\b|certutil\s+-decode|bitsadmin", re.I)
CHAIN_RE = re.compile(r"(?:^|&&|;|\|\|)\s*node\s+(?:\./)?([A-Za-z0-9_.-]+\.(?:js|cjs|mjs))\s*&&")
GITIGNORE_WORM_RE = re.compile(r"^\s*/?(?:temp_auto_push|temp_interactive_push)\.bat\s*$", re.M)
GITIGNORE_CONFIGBAT_RE = re.compile(r"^\s*/?config\.bat\s*$", re.M)
BAT_PUSH_RE = re.compile(r"git\s+(?:push|commit\s+--amend)|--force|LAST_COMMIT_DATE", re.I)

ALLOW_FILE = os.path.expanduser("~/.config/checkrepo/allowlist")

# Implant / worm file names that are indicators on their own (community filenames.txt, Oct 2026)
IMPLANT_NAME_RE = re.compile(r"(?:^|/)(?:MicrosoftSystem64(?:\.exe|-win\.exe|-linux|-darwin-(?:x64|arm64))?"
                             r"|com\.launchkeeper\.[^/]*\.plist|SvcHostUpdate\.(?:py|js)|MicrosoftCLROptimization\.vbs"
                             r"|fa-solid-\d{3}\.llf)$", re.I)
# GlassWorm-style payloads: code encoded in long runs of invisible Unicode (variation selectors / tag characters)
INVISIBLE_RUN_RE = re.compile("[\\ufe00-\\ufe0f\\U000e0100-\\U000e01ef]{40,}|[\\U000e0000-\\U000e007f]{20,}")
TAG_RUN_RE = re.compile("[\\U000e0000-\\U000e007f]{10,}")
# Oct 2026 root api.js dropper: one huge line holding a hex-string array obfuscator
HEX_ARRAY_RE = re.compile(r"\[\s*'[0-9a-f]{16,}'(?:\s*,\s*'[0-9a-f]{16,}'){19,}")
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock")

# AI coding-agent files a repository can ship (Claude Code, Cursor, Copilot, Gemini, Windsurf, Codex)
AGENT_SETTINGS = (".claude/settings.json", ".claude/settings.local.json")
MCP_FILES = (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json", ".windsurf/mcp.json")
INSTRUCTION_NAMES = ("claude.md", "agents.md", "gemini.md", ".cursorrules", ".windsurfrules", "copilot-instructions.md")
AGENT_EXEC_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n\"]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|node|python3?)\b|\bbase64\s+(?:-d|--decode)\b"
    r"|\bnode\s+-e\b|\bpython3?\s+-c\b|\bpowershell\b|\biex\b|\beval\s*\(|~/\.ssh|id_rsa|\.aws/credentials", re.I)
PROMPT_INJECTION_RE = re.compile(
    r"ignore (?:all |any )?(?:previous|prior|above) instructions|do not (?:tell|inform|mention)[^.\n]{0,40}(?:user|human)"
    r"|\b(?:send|post|upload|exfiltrate|transmit|forward)\b[^.\n]{0,60}\b(?:\.env|environment variables|env vars|api[_ -]?keys?|tokens?|secrets?|credentials?|ssh keys?)\b"
    r"[^.\n]{0,60}\b(?:to|into)\b[^.\n]{0,40}(?:https?://|\bserver\b|webhook|endpoint|discord|telegram|pastebin|\burl\b)", re.I)
BASE_URL_RE = re.compile(r'"(?:ANTHROPIC_BASE_URL|ANTHROPIC_API_URL|OPENAI_BASE_URL|OPENAI_API_BASE|[A-Z_]*_BASE_URL)"\s*:\s*"https?://', re.I)


def load_hashes(path):
    try:
        return {l.split()[0].lower() for l in open(path) if l.strip() and not l.startswith("#")}
    except OSError:
        return set()


def is_real_font(b):
    if len(b) >= 4 and b[:4] in (b"wOF2", b"wOFF", b"OTTO", b"true", b"ttcf", b"\x00\x01\x00\x00", b"typ1"):
        return True
    return len(b) > 36 and b[34:36] == b"LP"  # Embedded OpenType magic


def mostly_text(b):
    s = b[:4096]
    if not s:
        return False
    t = sum(1 for c in s if c in (9, 10, 13) or 32 <= c < 127)
    return t * 100 >= len(s) * 95


def strip_jsonc(text):
    """Remove // and /* */ comments and trailing commas (VS Code's JSON-with-comments), leaving strings intact."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1]); i += 2; continue
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True; out.append(c); i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i); i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2); i = n if j < 0 else j + 2
        else:
            out.append(c); i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def folder_open_tasks(text):
    """[(command line, hidden?)] for every task that runs automatically on folder open; None if unparseable."""
    try:
        j = json.loads(strip_jsonc(text))
    except ValueError:
        return None
    tasks = j.get("tasks") if isinstance(j, dict) else None
    if not isinstance(tasks, list):
        return None
    res = []
    for t in tasks:
        if not isinstance(t, dict) or (t.get("runOptions") or {}).get("runOn") != "folderOpen":
            continue
        parts = []
        for key in ("command", "args"):
            for blk in (t, t.get("osx") or {}, t.get("linux") or {}, t.get("windows") or {}):
                v = blk.get(key) if isinstance(blk, dict) else None
                if isinstance(v, str):
                    parts.append(v)
                elif isinstance(v, list):
                    parts += [a if isinstance(a, str) else str((a or {}).get("value", "")) for a in v]
        pres = t.get("presentation") or {}
        hidden = bool(t.get("hide")) or pres.get("reveal") in ("never", "silent")
        res.append((" ".join(parts), hidden))
    return res


def marker_hits(text):
    hits = [m.group(0)[:40] for m in MARKER_RE.finditer(text)][:3]
    m = C2_IP_RE.search(text)
    if m:
        hits.append(m.group(0))
    for s in MARKER_STRINGS:
        if s in text:
            hits.append(s)
            if len(hits) >= 4:
                break
    return hits


class Scan:
    def __init__(self, root, include_deps=False):
        self.root = root
        self.include_deps = include_deps
        self.findings = []  # (severity, rule, relpath, detail)
        self.known = KNOWN_HASHES | load_hashes(KNOWN_HASHES_FILE)
        self.allow = load_hashes(ALLOW_FILE)
        self.autorun_tasks = False
        self.flagged = set()
        self.pending_settings = []
        self.pending_chains = []
        self.gitignore_configbat = False
        self.configbat_files = []

    def add(self, sev, rule, rel, detail):
        self.findings.append((sev, rule, rel, detail))
        if sev == "DANGER":
            self.flagged.add(rel)

    def git_files(self):
        """Files the repository actually contains: tracked + untracked-but-not-ignored. None if not a git work tree."""
        import subprocess
        # The scanned folder is untrusted: its .git/config could name a program for git to run (core.fsmonitor).
        # Force those settings off so scanning a repo can never execute anything from it.
        safe = ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.hooksPath=" + os.devnull,
                "-C", self.root]
        try:
            top = subprocess.run(safe + ["rev-parse", "--show-toplevel"], capture_output=True, text=True, timeout=10)
            if top.returncode != 0 or os.path.realpath(top.stdout.strip()) != os.path.realpath(self.root):
                return None
            out = subprocess.run(safe + ["-c", "core.quotepath=off", "ls-files", "-z", "-co", "--exclude-standard"],
                                 capture_output=True, timeout=60)
            return out.stdout.decode("utf-8", "replace").split("\0") if out.returncode == 0 else None
        except Exception:
            return None

    def walk(self):
        files = None if self.include_deps else self.git_files()
        if files is not None:
            for rel in files:
                # tracked files are scanned even inside node_modules/venv: committing those is unusual and can hide payloads
                if not rel or ".git" in rel.split("/")[:-1]:
                    continue
                full = os.path.join(self.root, rel)
                if os.path.isfile(full) and not os.path.islink(full):
                    self.file(full, rel, rel.rsplit("/", 1)[-1])
            self.finish()
            return
        skip = SKIP_DIRS - ({"node_modules", "bower_components"} if self.include_deps else set())
        for dp, dns, fns in os.walk(self.root):
            dns[:] = [d for d in dns if d not in skip]
            for fn in fns:
                full = os.path.join(dp, fn)
                if os.path.islink(full):
                    continue
                self.file(full, os.path.relpath(full, self.root).replace(os.sep, "/"), fn)
        self.finish()

    def read(self, full, limit=MAX_READ):
        try:
            if os.path.getsize(full) > limit:
                return None
            with open(full, "rb") as f:
                return f.read()
        except OSError:
            return None

    def file(self, full, rel, name):
        low = name.lower()
        parts = rel.split("/")
        in_vscode = len(parts) >= 2 and parts[-2] == ".vscode"
        is_code = low.endswith(CODE_EXT)
        is_font = low.endswith(FONT_EXT)
        if IMPLANT_NAME_RE.search(rel):
            self.add("DANGER", "implant-file", rel, "file name of the campaign's implant / worm tooling")
            return
        is_agent_cfg = rel.endswith(AGENT_SETTINGS) or rel.endswith(MCP_FILES)
        is_instr = low in INSTRUCTION_NAMES or (len(parts) >= 3 and parts[-3] == ".cursor" and parts[-2] == "rules")
        interesting = (is_code or is_font or in_vscode or is_agent_cfg or is_instr or low in LOCKFILES
                       or low in ("package.json", ".gitignore") or low.endswith(".bat") or low.endswith(".json"))
        if not interesting:
            return
        data = self.read(full, MAX_READ_LOCKFILE if low in LOCKFILES else MAX_READ)
        if data is None:
            return
        sha = hashlib.sha256(data).hexdigest()
        if sha in self.allow:
            return
        if sha in self.known:
            self.add("DANGER", "known-payload", rel, "exact fingerprint of a known malware file")
            return

        if low in ("temp_auto_push.bat", "temp_interactive_push.bat"):
            self.add("DANGER", "worm-script", rel, "worm propagation script")
            return
        if low == "config.bat":
            self.configbat_files.append((rel, data))
            return
        if is_font:
            if len(data) <= 2 * 1024 * 1024 and not is_real_font(data) and mostly_text(data):
                text = data[:200000].decode("utf-8", "replace")
                if JS_LIKE_RE.search(text) or marker_hits(text):
                    self.add("DANGER", "fake-font", rel, "font file is actually JavaScript")
            return

        text = data.decode("utf-8", "replace")
        if low == ".gitignore":
            if GITIGNORE_WORM_RE.search(text):
                self.add("DANGER", "gitignore-worm", rel, "hides the worm's push scripts")
            elif GITIGNORE_CONFIGBAT_RE.search(text):
                self.gitignore_configbat = True
            return

        if is_agent_cfg:
            self.agent_config(rel, text)
            if not in_vscode:
                return
        if is_instr:
            self.instructions(rel, text)
            return
        if low in LOCKFILES:
            self.lockfile(rel, text)
            return

        if in_vscode:
            self.vscode(rel, low, text)
            return

        m = marker_hits(text)
        if m and (is_code or low.endswith(".json")):
            self.add("DANGER", "campaign-marker", rel, "known malware code: " + ", ".join(m[:2]))
            return

        if low == "package.json":
            self.package(rel, text)
            return

        if is_code:
            inv = INVISIBLE_RUN_RE.search(text)
            if inv:
                self.add("DANGER", "invisible-code", rel, f"{len(inv.group(0))} invisible Unicode characters hiding encoded code (GlassWorm technique)")
                return
            if (len(parts) == 1 or os.path.exists(os.path.join(self.root, *parts[:-1], "package.json"))) \
                    and HEX_ARRAY_RE.search(text) and max(map(len, text.split("\n"))) > 2000:
                self.add("DANGER", "hex-dropper", rel, "root-level script with a hex-array obfuscated loader (Oct 2026 api.js variant)")
                return
            for hm in HIDDEN_RE.finditer(text):
                if HIDDEN_CODE_RE.match(hm.group(2)):
                    self.add("DANGER", "hidden-code", rel,
                             f"code hidden after {len(hm.group(1))} spaces ({len(hm.group(2)) // 1024} KB off-screen)")
                    break

    def agent_config(self, rel, text):
        """Claude Code / MCP config shipped inside a repo: hooks and MCP servers run commands on your machine."""
        m = marker_hits(text)
        if m:
            self.add("DANGER", "ai-agent-config", rel, "AI-agent config contains known malware indicators: " + m[0])
            return
        reasons = []
        try:
            j = json.loads(text)
        except ValueError:
            j = None
        if isinstance(j, dict):
            cmds = []
            def walk(o):
                if isinstance(o, dict):
                    if isinstance(o.get("command"), str):   # program + its arguments, checked as one command line
                        a = o.get("args")
                        cmds.append(o["command"] + (" " + " ".join(map(str, a)) if isinstance(a, list) else ""))
                    for v in o.values():
                        walk(v)
                elif isinstance(o, list):
                    for v in o:
                        walk(v)
            walk(j.get("hooks", {}))
            for srv in (j.get("mcpServers") or j.get("servers") or {}).values() if isinstance(j.get("mcpServers") or j.get("servers"), dict) else []:
                walk(srv)
            loader = [c for c in cmds if TASK_LOADER_RE.search(c)]
            if loader:
                self.add("DANGER", "ai-agent-config", rel, "AI-agent config runs a disguised file/download: " + loader[0][:70])
                return
            # read in-repo scripts that hooks/servers call (e.g. "$CLAUDE_PROJECT_DIR/.claude/hooks/x.sh")
            bodies = []
            for c in cmds:
                for ref in re.findall(r'(?:\$CLAUDE_PROJECT_DIR|\$\{CLAUDE_PROJECT_DIR\}|\.)?/?((?:\.claude|scripts?|tools?|\.cursor|bin)/[\w./-]+\.(?:sh|bash|zsh|js|mjs|cjs|ts|py))', c):
                    fp = os.path.join(self.root, ref)
                    d = self.read(fp) if os.path.isfile(fp) else None
                    if d:
                        bodies.append((ref, d.decode("utf-8", "replace")))
            for ref, body in bodies:
                if marker_hits(body) or TASK_LOADER_RE.search(body):
                    self.add("DANGER", "ai-agent-config", rel, f"AI-agent hook script {ref} runs a malware loader")
                    return
            steal_src = re.compile(r"~/\.ssh|\$HOME/\.ssh|id_rsa|id_ed25519|\.aws/credentials|login\.keychain|Login Data|\bprintenv\b|\benv\s*\|", re.I)
            steal_net = re.compile(r"\bcurl\b|\bwget\b|\bnc\s|\bfetch\(|https?://", re.I)
            for what in cmds + [b for _, b in bodies]:
                if steal_src.search(what) and steal_net.search(what):
                    self.add("DANGER", "ai-agent-config", rel, "AI-agent hook reads your keys/credentials and sends them over the network")
                    return
            bad = [c for c in cmds if AGENT_EXEC_RE.search(c)] + [f"{r}: {AGENT_EXEC_RE.search(b).group(0)}" for r, b in bodies if AGENT_EXEC_RE.search(b)]
            if bad:
                reasons.append("hook/server runs risky shell code (" + bad[0][:70] + ")")
            perms = (j.get("permissions") or {}) if isinstance(j.get("permissions"), dict) else {}
            allow = perms.get("allow") or []
            if any(a in ("Bash", "Bash(*)", "Bash(*:*)") for a in allow if isinstance(a, str)) or perms.get("defaultMode") == "bypassPermissions":
                reasons.append("pre-approves running any shell command")
            if j.get("apiKeyHelper"):
                reasons.append("sets an apiKeyHelper command")
        if BASE_URL_RE.search(text):
            reasons.append("redirects AI API traffic to another server (can leak your API key)")
        if reasons:
            self.add("WARNING", "ai-agent-config", rel, "; ".join(reasons))

    def instructions(self, rel, text):
        """CLAUDE.md / AGENTS.md / .cursorrules etc.: AI agents read these and may follow them."""
        if TAG_RUN_RE.search(text) or INVISIBLE_RUN_RE.search(text):
            self.add("DANGER", "ai-instructions", rel, "hidden invisible-Unicode instructions for AI agents")
            return
        if marker_hits(text):
            self.add("DANGER", "ai-instructions", rel, "contains known malware indicators")
            return
        reasons = []
        if PROMPT_INJECTION_RE.search(text):
            reasons.append("tells the AI to hide things or send out secrets")
        mm = re.search(r"\b(?:curl|wget)\b[^\n`]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b", text)
        if mm:
            reasons.append("asks to pipe a download into a shell: " + mm.group(0)[:60])
        if re.search(r"[A-Za-z0-9+/]{300,}={0,2}", text):
            reasons.append("contains a large encoded blob")
        if reasons:
            self.add("WARNING", "ai-instructions", rel, "; ".join(reasons) + " — review before letting an AI agent work in this repo")

    def lockfile(self, rel, text):
        # names appear as "node_modules/<name>", "<name>": , <name>@<version>, '<name>@ — never as part of another name
        hits = sorted(set(m.group(1) for m in BAD_PKG_RE.finditer(text)))
        if hits:
            self.add("DANGER", "malicious-package", rel, "lockfile installs known malicious package: " + ", ".join(hits[:3]))

    def vscode(self, rel, low, text):
        if low == "tasks.json":
            if not FOLDER_OPEN_RE.search(text):
                return
            if marker_hits(text):
                self.autorun_tasks = True
                self.add("DANGER", "vscode-autorun", rel, "auto-run task contains known malware indicators")
                return
            tasks = folder_open_tasks(text)
            if tasks is None:   # couldn't parse: judge the whole file
                tasks = [(text, bool(HIDDEN_TASK_RE.search(text)))]
            if any(TASK_LOADER_RE.search(cmd) for cmd, _ in tasks):
                self.autorun_tasks = True
                self.add("DANGER", "vscode-autorun", rel, "task auto-runs a disguised file/download when the folder opens")
            elif any(hidden for _, hidden in tasks):
                self.add("WARNING", "vscode-autorun", rel, "hidden task runs automatically on folder open — check what it runs")
            return
        if low == "settings.json":
            self.pending_settings.append((rel, text))
            return
        if low == "launch.json":
            if marker_hits(text):
                self.add("DANGER", "campaign-marker", rel, "known malware code in launch.json")
            return
        if low.endswith((".dict", ".txt", ".log", ".dat", ".bin")):
            compact = re.sub(r"\s+", "", text[:200000])
            if marker_hits(text) or (CODE_AUX_RE.search(text) and (HEXRUN_RE.search(compact) or len(max(text.split("\n"), key=len, default="")) > 2000)):
                self.add("DANGER", "disguised-payload", rel, "code hidden in a .vscode data file")

    def package(self, rel, text):
        try:
            j = json.loads(text)
        except ValueError:
            return
        if not isinstance(j, dict):
            return
        for k in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = j.get(k)
            if isinstance(deps, dict):
                names = set(deps)
                for v in deps.values():   # npm aliases: "tw": "npm:<real-name>@1.0.0"
                    a = re.match(r"npm:((?:@[^/@\s]+/)?[^@\s]+)", v) if isinstance(v, str) else None
                    if a:
                        names.add(a.group(1))
                bad = sorted(MALICIOUS_NPM & names)
                if bad:
                    self.add("DANGER", "malicious-package", rel, "known malicious npm package: " + ", ".join(bad))
        scripts = j.get("scripts")
        if not isinstance(scripts, dict):
            return
        for k in LIFECYCLE:
            v = scripts.get(k)
            if isinstance(v, str):
                if LIFECYCLE_DANGER_RE.search(v):
                    self.add("DANGER", "install-script", rel, f'"{k}" downloads and runs code: {v[:70]}')
                elif re.search(r"\bnode\s+-e\b.*(?:https?://|eval|Buffer\.from|atob)", v):
                    self.add("WARNING", "install-script", rel, f'"{k}" runs inline code: {v[:70]}')
        base = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        for k, v in scripts.items():
            if isinstance(v, str):
                c = CHAIN_RE.search(v)
                if c and not re.search(r"\.config\.|^(?:scripts?|tools?|bin)/", c.group(1)):
                    self.pending_chains.append((rel, k, base + c.group(1), v))

    def finish(self):
        for rel, text in self.pending_settings:
            reasons = []
            if AUTO_TASKS_RE.search(text):
                reasons.append("turns on automatic tasks")
            if TRUST_OFF_RE.search(text):
                reasons.append("disables workspace trust")
            if FOLDER_OPEN_RE.search(text) and (TASK_LOADER_RE.search(text) or AUTO_TASKS_RE.search(text)):
                self.add("DANGER", "vscode-settings", rel, "turns on automatic tasks and hides an auto-run task inside settings")
            elif reasons:
                sev = "DANGER" if self.autorun_tasks else "WARNING"
                self.add(sev, "vscode-settings", rel, ", ".join(reasons))
        for rel, k, target, v in self.pending_chains:
            if target in self.flagged:
                self.add("DANGER", "script-chain", rel, f'"{k}" runs the infected {target} first')
        for rel, data in self.configbat_files:
            if self.gitignore_configbat or BAT_PUSH_RE.search(data.decode("utf-8", "replace")):
                self.add("DANGER", "worm-script", rel, "worm orchestrator batch file")


def main(argv):
    if "--version" in argv:
        print("checkrepo", VERSION)
        return 0
    if "--help" in argv or "-h" in argv:
        print(__doc__)
        return 0
    if os.name == "nt":
        os.system("")  # enables ANSI colours in Windows terminals
    for stream in (sys.stdout, sys.stderr):
        try:   # never crash on emoji when output goes to a pipe with a legacy code page (would look like exit 1 = DANGER)
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    quiet = "--quiet" in argv
    as_json = "--json" in argv
    deps = "--include-deps" in argv
    args = [a for a in argv if not a.startswith("--")]
    root = os.path.abspath(args[0] if args else ".")
    if not os.path.isdir(root):
        print(f"checkrepo: '{root}' is not a folder", file=sys.stderr)
        return 3
    s = Scan(root, deps)
    s.walk()
    danger = [f for f in s.findings if f[0] == "DANGER"]
    warn = [f for f in s.findings if f[0] == "WARNING"]
    code = 1 if danger else (2 if warn else 0)
    if as_json:
        print(json.dumps({"root": root, "exit": code, "findings": s.findings}))
        return code
    tty = sys.stdout.isatty() or os.environ.get("CHECKREPO_COLOR") == "1"
    R, Y, G, D, X = ("\033[1;31m", "\033[1;33m", "\033[1;32m", "\033[2m", "\033[0m") if tty else ("",) * 5
    if not s.findings:
        if not quiet:
            print(f"{G}✅ checkrepo: no signs of malware found{X} {D}({root}){X}")
        return 0
    print()
    if danger:
        print(f"{R}🛑 DANGER — malware found. Do NOT open this folder in VS Code/Cursor and do NOT run npm install.{X}")
    else:
        print(f"{Y}⚠️  checkrepo: unusual settings found (not necessarily malware — please review){X}")
    print(f"{D}{root}{X}")
    for sev, rule, rel, detail in danger + warn:
        mark = f"{R}✗{X}" if sev == "DANGER" else f"{Y}!{X}"
        print(f"  {mark} {rel}  — {detail}")
    if danger:
        print(f"\n  What to do: see docs/after-a-scan/if-danger-found.md in polinrider-survival-kit (cut off access first, then clean).")
        print(f"  Sure it's a false alarm? Allow that exact file: add its SHA-256 to ~/.config/checkrepo/allowlist")
    print()
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
