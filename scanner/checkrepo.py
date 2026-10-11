#!/usr/bin/env python3
"""checkrepo — read-only scanner for PolinRider / Contagious Interview / TasksJacker / GlassWorm-style malware.

Part of Ardvane (MIT License).

It NEVER executes anything from the scanned folder; it only reads bytes. Works on macOS, Linux and Windows
(Python 3.8+, no dependencies).

Severity:
  DANGER  — specific evidence of the campaign (blocks safe-clone and push when used with the git hooks)
  WARNING — unusual but can be legitimate (shown, never blocks)

Exit code: 0 clean, 1 danger found, 2 warnings only, 3 usage error, 4 the scan could not finish (never "clean").

Usage:
  checkrepo [folder]                 scan a folder (default: current folder)
  checkrepo --quiet [folder]         print only when something is found (used by git hooks)
  checkrepo --json [folder]          machine-readable output
  checkrepo --summary [folder]       one line for scripts: "<exit code> <first findings>" (4 if the scan failed)
  checkrepo --include-deps [folder]  also scan node_modules (slow; for deep audits)
  checkrepo --all-files [folder]     scan every file but .git, whatever its folder (used by safe clone)
  checkrepo --version | --help

In a git work tree it scans what the repository contains (tracked + new non-ignored files) plus ignored files in
places editors and AI agents read (.vscode, .claude, config files, fonts), so generated build output is skipped.
Any other folder (e.g. an unzipped download) is scanned fully. A file that can't be analysed is reported as a
warning instead of stopping the scan, and files too large to read fully are checked at both ends.

False alarm? Add the file's SHA-256 to ~/.config/checkrepo/allowlist (one per line). Allow-listing is by exact
content, so if the file ever changes it is scanned again.

Detection rules are modelled on real samples from the campaign plus the public research and community
detectors credited in the repository's README.
"""
VERSION = "1.0.0"
import collections
import hashlib
import json
import os
import re
import stat
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
C2_IP_SET = set(C2_IPS)
# Indicators are pulled out of a file once and looked up in a set, so matching costs the same for 20 entries or
# 20,000 (the detection feed can be large). IPs only count when they stand alone (not inside a version like 1.136.0.9.8).
IPV4_RE = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
HOST_TOKEN_RE = re.compile(r"(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}", re.I)

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

# Package names in a lockfile: "node_modules/<name>", "<name>":, <name>@<ver>, npm aliases "npm:<name>@", pnpm v6 keys
# "/<name>@". Each match is a whole name, so "@acme/<name>" or "<name>-extra" never count as <name>.
PKG_TOKEN_RE = re.compile(r'(?:node_modules/|npm:|(?m:^)[ \t]*/|(?<![\w@/.~-]))((?:@[\w.~-]+/)?[\w.~-]+)(?=["\'@:\s])')


def npm_names_in(text):
    """Known-malicious npm packages named in a lockfile or manifest."""
    return {m.group(1) for m in PKG_TOKEN_RE.finditer(text)} & MALICIOUS_NPM


def _load_feed():
    """The signed detection feed (feed.py): new indicators between releases. Added to the built-in ones above, never
    replacing them. None without a valid feed - or with ARDVANE_NO_FEED set (the self-test runs on built-ins only)."""
    if os.environ.get("ARDVANE_NO_FEED"):
        return None
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import feed
        return feed.cached()
    except Exception:            # no feed module next to this file, or an unreadable feed: built-in indicators only
        return None


FEED = _load_feed()
FEED_HOSTS = set(FEED["hosts"]) if FEED else set()
if FEED:
    KNOWN_HASHES |= set(FEED["hashes"])
    MARKER_STRINGS += [m for m in FEED["markers"] if m not in MARKER_STRINGS]
    C2_IP_SET |= set(FEED["ips"])
    MALICIOUS_NPM |= set(FEED["npm"])

# ---------------------------------------------------------------- file classes
SKIP_DIRS = {".git", "node_modules", "bower_components", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache"}
CODE_EXT = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx")
FONT_EXT = (".woff", ".woff2", ".ttf", ".otf", ".eot", ".llf", ".fnt")
# Folders whose files editors and AI agents run or obey just because the project was opened
EDITOR_DIRS = {".vscode", ".claude", ".cursor", ".gemini", ".windsurf"}
# Build-tool config files: they run on every `npm run dev`, which is why the worm appends its code to them
CONFIG_NAME_RE = re.compile(r"(?:^|[._-])config\.[cm]?[jt]s$|^\.?[\w-]+rc\.[cm]?js$")
MB = 1024 * 1024
MAX_READ = 5 * MB              # read whole files up to this size ...
MAX_READ_LOCKFILE = 50 * MB    # (monorepo lockfiles are often 5-20 MB)
SAMPLE = 2 * MB                # ... above it, read the first and last SAMPLE bytes: payloads sit at either end
MAX_HASH = 512 * MB            # files are fingerprinted (allow-list / known payloads) up to this size
MAX_LINKED_FILES = 2000        # files read behind one symlinked editor folder
EXIT_CLEAN, EXIT_DANGER, EXIT_WARNING, EXIT_USAGE, EXIT_ERROR = range(5)

# Files git ignores that are scanned anyway in a repository: editors and agents read them even though they are
# never committed (e.g. Claude Code ignores .claude/settings.local.json itself), and malware likes to hide there.
SENSITIVE_PATHSPECS = tuple(":(glob,icase)" + p for p in (
    "**/.vscode/**", "**/.claude/**", "**/.cursor/**", "**/.gemini/**", "**/.windsurf/**", "**/.mcp.json",
    "**/*config.*", "**/*rc.js", "**/fonts/**", "**/package.json")) + (":(exclude,glob)**/node_modules/**",)

# Payload appended after a long run of whitespace: real samples use 149–776 spaces then 25–40 KB of code. The run may
# start a line, and may use any character JavaScript treats as a space (no-break, em/ideographic spaces, BOM).
HIDDEN_RE = re.compile(r"([ \t\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000\ufeff]{60,})(\S[^\n]{300,})")
# The payload begins immediately after the whitespace with one of the campaign's loader openings.
HIDDEN_CODE_RE = re.compile(r"(?:global\[\s*['\"]|global\.[A-Za-z_]\w*\s*=\s*['\"]|(?:var|let|const)\s+_0x[0-9a-f]{4}|function\s+_0x[0-9a-f]{4}|\(function\s*\(\s*_0x[0-9a-f]{4}|eval\(\s*(?:atob|Buffer\.from|String\.fromCharCode))")
# In a build-tool config file, this much code this far off-screen is hidden whatever it starts with
HIDDEN_CONFIG_SPACES, HIDDEN_CONFIG_CODE = 150, 2000

JS_LIKE_RE = re.compile(r"global\[|global\.[A-Za-z_]+\s*=|_0x[0-9a-f]{4}|\brequire\(|\bfunction\b")
FOLDER_OPEN_RE = re.compile(r'"runOn"\s*:\s*"folderOpen"')
# Shell commands that fetch and run code, or the worm's "find node on any OS" prologue. Applied to individual
# commands (auto-run tasks, AI-agent hooks / MCP servers), never to whole files, so unrelated URLs elsewhere in a file
# can't trigger it. Known C2 hosts (e.g. the *.vercel.app loaders) are matched exactly by MARKER_STRINGS instead.
SHELL_LOADER_RE = re.compile(
    r"command -v node[^\"]*\|\|\s*\(?\s*where node\s*>\s*nul"
    r"|\b(?:curl|wget)\b[^\"]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|cmd)\b"
    r"|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\"]*\|\s*(?:iex|invoke-expression)\b", re.I)
# `node [flags] <file> [args]`: everything after node up to the next shell separator
NODE_RUN_RE = re.compile(r"\bnode(?:\.exe)?[ \t]+([^&|;\n]+)", re.I)
# The file node runs: a path ending in an extension (it may contain spaces, never " -"), else the first word
SCRIPT_PATH_RE = re.compile(r"""^["']?((?:(?! -)[^"'`])+?\.[A-Za-z0-9]{1,6})["']?(?=[\s"'`,;)\]}]|$)|^["']?([^\s"'`,;)\]}]+)""")
NODE_INLINE_FLAGS = {"-e", "--eval", "-p", "--print"}             # the next argument is code, not a file
NODE_PRELOAD_FLAGS = {"-r", "--require", "--import", "--loader"}  # the next argument is a file node runs too
NODE_RUNNABLE_EXT = CODE_EXT + (".json", ".node")
PAYLOAD_EXT = FONT_EXT + (".dict",)   # what the campaign's loaders actually run
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
AGENT_SCRIPT_RE = re.compile(r'(?:\$CLAUDE_PROJECT_DIR|\$\{CLAUDE_PROJECT_DIR\}|\.)?/?((?:\.claude|scripts?|tools?|\.cursor|bin)/[\w./-]+\.(?:sh|bash|zsh|js|mjs|cjs|ts|py))')
STEAL_SRC_RE = re.compile(r"~/\.ssh|\$HOME/\.ssh|id_rsa|id_ed25519|\.aws/credentials|login\.keychain|Login Data|\bprintenv\b|\benv\s*\|", re.I)
STEAL_NET_RE = re.compile(r"\bcurl\b|\bwget\b|\bnc\s|\bfetch\(|https?://", re.I)
PROMPT_INJECTION_RE = re.compile(
    r"ignore (?:all |any )?(?:previous|prior|above) instructions|do not (?:tell|inform|mention)[^.\n]{0,40}(?:user|human)"
    r"|\b(?:send|post|upload|exfiltrate|transmit|forward)\b[^.\n]{0,60}\b(?:\.env|environment variables|env vars|api[_ -]?keys?|tokens?|secrets?|credentials?|ssh keys?)\b"
    r"[^.\n]{0,60}\b(?:to|into)\b[^.\n]{0,40}(?:https?://|\bserver\b|webhook|endpoint|discord|telegram|pastebin|\burl\b)", re.I)
BASE_URL_RE = re.compile(r'"(?:ANTHROPIC_BASE_URL|ANTHROPIC_API_URL|OPENAI_BASE_URL|OPENAI_API_BASE|[A-Z_]*_BASE_URL)"\s*:\s*"https?://', re.I)
# Prefixes that commands use for "the project folder"
PROJECT_DIR_RE = re.compile(r"^(?:\$\{?(?:CLAUDE_PROJECT_DIR|workspaceFolder|PWD)\}?|\$\{workspaceRoot\})[/\\]")


# ---------------------------------------------------------------- small helpers
def load_hashes(path):
    try:
        return {l.split()[0].lower() for l in open(path) if l.strip() and not l.startswith("#")}
    except OSError:
        return set()


Blob = collections.namedtuple("Blob", "data size complete sha")


def read_sample(path, limit=MAX_READ):
    """Read a regular file: all of it up to `limit` bytes, else its first and last SAMPLE bytes (complete=False).
    The SHA-256 always covers the whole file (up to MAX_HASH). None for anything that is not a regular file - a
    named pipe would block forever - or can't be read."""
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            return None
        with open(path, "rb") as f:
            if st.st_size <= limit:
                data = f.read()
                return Blob(data, len(data), True, hashlib.sha256(data).hexdigest())
            head = f.read(SAMPLE)
            f.seek(max(st.st_size - SAMPLE, SAMPLE))
            tail = f.read(SAMPLE)
            h, sha = hashlib.sha256(), None
            if st.st_size <= MAX_HASH:
                f.seek(0)
                for chunk in iter(lambda: f.read(MB), b""):
                    h.update(chunk)
                sha = h.hexdigest()
            return Blob(head + b"\n" + tail, st.st_size, False, sha)
    except OSError:
        return None


def decode(data):
    return data.decode("utf-8", "replace")


def looks_like_text(data):
    """True for text in any language (valid UTF-8 or mostly printable ASCII), False for binary data."""
    s = data[:65536]
    if not s or b"\0" in s:
        return False
    try:
        s.decode("utf-8")
        return True
    except UnicodeDecodeError as e:
        if e.start >= len(s) - 3:          # only the sample cut a multi-byte character in half
            return True
    return sum(1 for c in s if c in (9, 10, 13) or 32 <= c < 127) * 100 >= len(s) * 95


def looks_obfuscated(text):
    """The campaign's obfuscator: _0x… names inside a `while(!![])` string-array rotation."""
    return "_0x" in text and "while(!![])" in text


def looks_like_code(data):
    """Bytes that are JavaScript (or carry the campaign's markers) - for files that should not be code at all."""
    text = decode(data)
    return bool(marker_hits(text)) or (looks_like_text(data) and JS_LIKE_RE.search(text) is not None)


def _u32(b, i, order="big"):
    return int.from_bytes(b[i:i + 4], order)


def _sfnt_ok(b, off, size):
    """A TrueType/OpenType table directory at `off`: a sane table count, and every table inside the file."""
    if off + 12 > len(b):
        return False
    n = int.from_bytes(b[off + 4:off + 6], "big")
    if not 1 <= n <= 100 or off + 12 + 16 * n > min(len(b), size):
        return False
    for e in range(off + 12, off + 12 + 16 * n, 16):
        if not all(32 <= c < 127 for c in b[e:e + 4]) or _u32(b, e + 8) + _u32(b, e + 12) > size:
            return False
    return True


def valid_font(b, size):
    """True only for a structurally valid font file. A magic number alone is not enough: `true` is both a TrueType
    signature and the start of valid JavaScript, so the header must also describe a file of exactly this shape."""
    if len(b) < 12:
        return False
    tag = b[:4]
    if tag in (b"wOFF", b"wOF2"):
        return _u32(b, 8) == size                                  # WOFF header: total length
    if tag in (b"\x00\x01\x00\x00", b"OTTO", b"true", b"typ1"):
        return _sfnt_ok(b, 0, size)
    if tag == b"ttcf":                                             # font collection: every font's directory
        n = _u32(b, 8)
        offs = [_u32(b, 12 + 4 * i) for i in range(n)] if 1 <= n <= 256 and 12 + 4 * n <= len(b) else []
        return bool(offs) and all(_sfnt_ok(b, o, size) for o in offs)
    if len(b) >= 36 and b[34:36] == b"LP":                         # Embedded OpenType: EOTSize, little-endian
        return _u32(b, 0, "little") == size
    return False


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


def load_json(text, jsonc=False):
    """Parsed JSON, or None. With jsonc, comments and trailing commas are allowed (VS Code / Cursor config).
    Hostile input (e.g. 100,000 nested brackets) gives None instead of an exception."""
    for attempt in ((text, strip_jsonc) if jsonc else (text,)):
        try:
            return json.loads(attempt if isinstance(attempt, str) else attempt(text))
        except (ValueError, RecursionError):
            continue
    return None


def as_dict(v):
    return v if isinstance(v, dict) else {}


def as_list(v):
    return v if isinstance(v, list) else []


def iter_dicts(obj):
    """Every dict inside a parsed JSON document, depth-first, without recursion (input can be nested deeply)."""
    stack = [obj]
    while stack:
        o = stack.pop()
        if isinstance(o, dict):
            yield o
            stack.extend(o.values())
        elif isinstance(o, list):
            stack.extend(o)


def command_line(d):
    """`command` + `args` of a task / hook / MCP server entry as one command line ('' if it has none)."""
    parts = []
    for key in ("command", "args"):
        v = d.get(key)
        if isinstance(v, str):
            parts.append(v)
        else:     # VS Code allows {"value": "...", "quoting": ...} objects among the arguments
            parts += [a if isinstance(a, str) else str(as_dict(a).get("value", "")) for a in as_list(v)]
    return " ".join(p for p in parts if p)


def node_scripts(cmd):
    """Files a command line runs with node: `node [flags] <file>`, preloads (`-r <file>`) included."""
    found = []
    for m in NODE_RUN_RE.finditer(cmd):
        rest = m.group(1).strip()
        while rest.startswith("-"):
            flag, _, rest = rest.partition(" ")
            name = flag.split("=", 1)[0]
            if name in NODE_INLINE_FLAGS:
                rest = ""
            elif name in NODE_PRELOAD_FLAGS:
                if "=" in flag:
                    found.append(flag.split("=", 1)[1].strip("\"'"))
                else:
                    value, _, rest = rest.lstrip().partition(" ")
                    found.append(value.strip("\"'"))
            rest = rest.lstrip()
        p = SCRIPT_PATH_RE.match(rest)
        if p:
            found.append((p.group(1) or p.group(2)).strip("\"'"))
    return [f for f in found if f]


def disguised(path, any_ext=True):
    """A file node is told to run although it isn't a script: anything in fonts/, a font or the campaign's .dict -
    and, for a real command line (any_ext), any other non-script file such as an image or a data file."""
    p = path.lower().replace("\\", "/")
    ext = os.path.splitext(p)[1]
    return "/fonts/" in "/" + p or ext in PAYLOAD_EXT or (any_ext and bool(ext) and ext not in NODE_RUNNABLE_EXT)


def loader_reason(cmd, freeform=False):
    """Why a command line is a malware loader (it runs a disguised file, or fetches and runs code), else None.
    freeform: `cmd` is free text such as a whole shell script, so comment lines are ignored and only the campaign's
    own payload types count (prose like "run `node x.ts`" must not look like a loader)."""
    if freeform:
        cmd = "\n".join(l for l in cmd.splitlines() if not l.lstrip().startswith(("#", "//")))
    for p in node_scripts(cmd):
        if disguised(p, any_ext=not freeform):
            return "runs " + p + " with node"
    m = SHELL_LOADER_RE.search(cmd)
    return m.group(0)[:70] if m else None


def folder_open_tasks(text):
    """[(command line, hidden?)] for every task that runs automatically on folder open; None if unparseable."""
    j = load_json(text, jsonc=True)
    tasks = j.get("tasks") if isinstance(j, dict) else None
    if not isinstance(tasks, list):
        return None
    res = []
    for t in tasks:
        if not isinstance(t, dict) or not is_folder_open(t):
            continue
        cmd = " ".join(filter(None, [command_line(t)] + [command_line(as_dict(t.get(os_)))
                                                          for os_ in ("osx", "linux", "windows")]))
        hidden = bool(t.get("hide")) or as_dict(t.get("presentation")).get("reveal") in ("never", "silent")
        res.append((cmd, hidden))
    return res


def is_folder_open(d):
    return d.get("runOn") == "folderOpen" or as_dict(d.get("runOptions")).get("runOn") == "folderOpen"


def settings_risks(text):
    """(turns on automatic tasks?, turns off workspace trust?, [auto-run commands hidden inside settings]).
    Read from the parsed values, so JSON escapes like "folder\\u004fpen" can't hide them."""
    j = load_json(text, jsonc=True)
    if isinstance(j, dict):
        return (j.get("task.allowAutomaticTasks") in ("on", True),
                j.get("security.workspace.trust.enabled") is False,
                [command_line(d) or "(task)" for d in iter_dicts(j) if is_folder_open(d)])
    return bool(AUTO_TASKS_RE.search(text)), bool(TRUST_OFF_RE.search(text)), [text] if FOLDER_OPEN_RE.search(text) else []


def feed_host(domain):
    """The feed host that `domain` is, or is a subdomain of (api.evil.example matches evil.example), else None."""
    labels = domain.lower().split(".")
    return next((h for h in (".".join(labels[i:]) for i in range(len(labels) - 1)) if h in FEED_HOSTS), None)


def marker_hits(text):
    hits = [m.group(0)[:40] for m in MARKER_RE.finditer(text)][:3]
    ip = next((i for i in IPV4_RE.findall(text) if i in C2_IP_SET), None)
    if ip:
        hits.append(ip)
    if FEED_HOSTS:
        host = next(filter(None, (feed_host(m.group(0)) for m in HOST_TOKEN_RE.finditer(text))), None)
        if host:
            hits.append(host)
    for s in MARKER_STRINGS:
        if s in text:
            hits.append(s)
            if len(hits) >= 4:
                break
    return hits


class Kind:
    """What a path is, decided once from its name. Case-insensitive, as macOS and Windows (and so VS Code) treat it:
    `.VSCode/Tasks.json` is the same file as `.vscode/tasks.json` there."""

    def __init__(self, rel):
        low = rel.lower()
        self.parts = low.split("/")
        self.name = self.parts[-1]
        dirs = self.parts[:-1]
        anchored = "/" + low
        self.in_vscode = bool(dirs) and dirs[-1] == ".vscode"
        self.in_editor_dir = any(d in EDITOR_DIRS for d in dirs) or self.name in EDITOR_DIRS
        self.is_code = self.name.endswith(CODE_EXT)
        self.is_font = self.name.endswith(FONT_EXT) or (self.name.endswith(".svg") and "fonts" in dirs)
        self.is_agent_cfg = anchored.endswith(tuple("/" + p for p in AGENT_SETTINGS + MCP_FILES))
        self.is_instr = self.name in INSTRUCTION_NAMES or (len(dirs) >= 2 and dirs[-2:] == [".cursor", "rules"])
        self.is_lockfile = self.name in LOCKFILES
        self.is_config = bool(CONFIG_NAME_RE.search(self.name))
        # files that run or configure code on their own: never skipped quietly
        self.sensitive = self.in_editor_dir or self.is_agent_cfg or self.is_config or self.is_font \
            or self.name in ("package.json", ".mcp.json")
        self.interesting = (self.sensitive or self.is_code or self.is_instr or self.is_lockfile
                            or self.name == ".gitignore" or self.name.endswith((".bat", ".json")))


# ---------------------------------------------------------------- the scan
class Scan:
    def __init__(self, root, include_deps=False, all_files=False):
        self.root = root
        self.root_real = os.path.realpath(root)
        self.include_deps = include_deps
        self.all_files = all_files          # every file but .git (a private checkout where everything is tracked)
        self.findings = []  # (severity, rule, relpath, detail)
        self.known = KNOWN_HASHES | load_hashes(KNOWN_HASHES_FILE)
        self.allow = load_hashes(ALLOW_FILE)
        self.autorun_tasks = False
        self.flagged = set()
        self.pending_settings = []
        self.runs = []                      # (rel of the file that runs it, label, script path as written)
        self.gitignore_configbat = False
        self.configbat_files = []

    def add(self, sev, rule, rel, detail):
        self.findings.append((sev, rule, rel, detail))
        if sev == "DANGER":
            self.flagged.add(rel)

    def guarded(self, rel, fn, *args):
        """Run one check; if the file breaks the analysis, report that instead of stopping the whole scan.
        (A crash used to end the scan with no result, which callers could mistake for clean.)"""
        try:
            fn(*args)
        except Exception as e:
            self.add("WARNING", "scan-error", rel, f"could not be analysed ({e.__class__.__name__}) - check this file by hand")

    def inside(self, path):
        real = os.path.realpath(path)
        return real == self.root_real or real.startswith(self.root_real.rstrip(os.sep) + os.sep)

    def resolve(self, ref, base=""):
        """In-repo relative path of a file named in a command (relative to `base` or the project root), else None."""
        ref = PROJECT_DIR_RE.sub("", ref.strip().strip("\"'")).replace("\\", "/")
        if not ref or ref.startswith(("/", "~", "$")) or re.match(r"^[A-Za-z]:", ref):
            return None
        for cand in ([base + "/" + ref] if base else []) + [ref]:
            full = os.path.join(self.root, *[p for p in cand.split("/") if p not in ("", ".")])
            if os.path.isfile(full) and self.inside(full):
                return os.path.relpath(os.path.realpath(full), self.root_real).replace(os.sep, "/")
        return None

    def git_files(self):
        """Files the repository contains (tracked + untracked-but-not-ignored) plus ignored files in places editors
        and agents read (SENSITIVE_PATHSPECS). None if the folder is not the top of a git work tree."""
        import subprocess
        # The scanned folder is untrusted: its .git/config could name a program for git to run (core.fsmonitor).
        # Force those settings off so scanning a repo can never execute anything from it.
        safe = ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.hooksPath=" + os.devnull,
                "-c", "core.quotepath=off", "-C", self.root]

        def ls(*args):
            out = subprocess.run(safe + ["ls-files", "-z"] + list(args), capture_output=True, timeout=60)
            if out.returncode != 0:
                raise OSError("git ls-files failed")
            return [f for f in out.stdout.decode("utf-8", "replace").split("\0") if f]
        try:
            top = subprocess.run(safe + ["rev-parse", "--show-toplevel"], capture_output=True, text=True, timeout=10)
            if top.returncode != 0 or os.path.realpath(top.stdout.strip()) != self.root_real:
                return None
            files = ls("-co", "--exclude-standard")
            seen = set(files)
            files += [f for f in ls("-o", "-i", "--exclude-standard", "--", *SENSITIVE_PATHSPECS) if f not in seen]
            return files
        except Exception:
            return None

    def walk(self):
        files = None if (self.include_deps or self.all_files) else self.git_files()
        if files is not None:
            for rel in files:
                # tracked files are scanned even inside node_modules/venv: committing those is unusual and can hide payloads
                if ".git" not in rel.split("/")[:-1]:
                    self.entry(os.path.join(self.root, rel), rel)
        else:
            skip = {".git"} if self.all_files else SKIP_DIRS - ({"node_modules", "bower_components"} if self.include_deps else set())
            for dp, dns, fns in os.walk(self.root):
                rel_dir = os.path.relpath(dp, self.root).replace(os.sep, "/")
                rel_of = (lambda n: n) if rel_dir == "." else (lambda n: rel_dir + "/" + n)
                for d in dns:                       # os.walk lists linked folders but never enters them
                    if os.path.islink(os.path.join(dp, d)):
                        self.entry(os.path.join(dp, d), rel_of(d))
                dns[:] = [d for d in dns if d not in skip and not os.path.islink(os.path.join(dp, d))]
                for fn in fns:
                    self.entry(os.path.join(dp, fn), rel_of(fn))
        self.guarded("(final checks)", self.finish)

    def entry(self, full, rel):
        if os.path.islink(full):
            self.guarded(rel, self.symlink, full, rel)
        elif os.path.isfile(full):
            self.guarded(rel, self.file, full, rel)

    def symlink(self, full, rel):
        """Links are not followed in general (they can point anywhere, e.g. your home folder). But editors and agents
        do follow a linked .vscode/.claude folder or config file, so those are read through the link."""
        if not Kind(rel).sensitive:
            return
        if not self.inside(full):
            self.add("WARNING", "symlink", rel, "links outside this project (to " + os.path.realpath(full)
                     + ") - editors and AI agents follow it; check what it points to")
            return
        target = os.path.realpath(full)
        if os.path.isfile(target):
            self.file(target, rel)
            return
        count = 0
        for dp, dns, fns in os.walk(target):
            dns[:] = [d for d in dns if d != ".git"]
            for fn in fns:
                f = os.path.join(dp, fn)
                count += 1
                if count > MAX_LINKED_FILES:
                    return
                if not os.path.islink(f):
                    sub = os.path.relpath(f, target).replace(os.sep, "/")
                    self.guarded(rel + "/" + sub, self.file, f, rel + "/" + sub)

    def file(self, full, rel):
        k = Kind(rel)
        if IMPLANT_NAME_RE.search(rel):
            self.add("DANGER", "implant-file", rel, "file name of the campaign's implant / worm tooling")
            return
        if not k.interesting:
            return
        blob = read_sample(full, MAX_READ_LOCKFILE if k.is_lockfile else MAX_READ)
        if blob is None:
            return
        if blob.sha in self.allow:
            return
        if blob.sha in self.known:
            self.add("DANGER", "known-payload", rel, "exact fingerprint of a known malware file")
            return
        data = blob.data
        if k.is_font:
            if not valid_font(data, blob.size) and looks_like_code(data):
                self.add("DANGER", "fake-font", rel, "font file is actually JavaScript")
            return
        if not blob.complete and (k.sensitive or k.is_lockfile):
            self.add("WARNING", "too-large", rel, f"{blob.size // MB} MB - too large to read fully; only its start and "
                     "end were checked. A file like this is rarely this big: look at it by hand")

        if k.name in ("temp_auto_push.bat", "temp_interactive_push.bat"):
            self.add("DANGER", "worm-script", rel, "worm propagation script")
            return
        if k.name == "config.bat":
            self.configbat_files.append((rel, data))
            return

        text = decode(data)
        if k.name == ".gitignore":
            if GITIGNORE_WORM_RE.search(text):
                self.add("DANGER", "gitignore-worm", rel, "hides the worm's push scripts")
            elif GITIGNORE_CONFIGBAT_RE.search(text):
                self.gitignore_configbat = True
            return

        if k.is_agent_cfg:
            self.agent_config(rel, text)
            if not k.in_vscode:
                return
        if k.is_instr:
            self.instructions(rel, text)
            return
        if k.is_lockfile:
            self.lockfile(rel, text)
            return

        if k.in_vscode:
            self.vscode(rel, k.name, text)
            return

        m = marker_hits(text)
        if m and (k.is_code or k.name.endswith(".json")):
            self.add("DANGER", "campaign-marker", rel, "known malware code: " + ", ".join(m[:2]))
            return

        if k.name == "package.json":
            self.package(rel, text)
            return

        if k.is_code:
            self.code(rel, k, text)

    def code(self, rel, k, text):
        inv = INVISIBLE_RUN_RE.search(text)
        if inv:
            self.add("DANGER", "invisible-code", rel, f"{len(inv.group(0))} invisible Unicode characters hiding encoded code (GlassWorm technique)")
            return
        parts = rel.split("/")
        if (len(parts) == 1 or os.path.exists(os.path.join(self.root, *parts[:-1], "package.json"))) \
                and HEX_ARRAY_RE.search(text) and max(map(len, text.split("\n"))) > 2000:
            self.add("DANGER", "hex-dropper", rel, "root-level script with a hex-array obfuscated loader (Oct 2026 api.js variant)")
            return
        for hm in HIDDEN_RE.finditer(text):
            spaces, code = len(hm.group(1)), hm.group(2)
            if HIDDEN_CODE_RE.match(code) or (k.is_config and spaces >= HIDDEN_CONFIG_SPACES and len(code) >= HIDDEN_CONFIG_CODE):
                self.add("DANGER", "hidden-code", rel, f"code hidden after {spaces} spaces ({len(code) // 1024} KB off-screen)")
                return

    def agent_config(self, rel, text):
        """Claude Code / MCP config shipped inside a repo: hooks, MCP servers and status lines run commands."""
        m = marker_hits(text)
        if m:
            self.add("DANGER", "ai-agent-config", rel, "AI-agent config contains known malware indicators: " + m[0])
            return
        reasons = []
        j = load_json(text, jsonc=True)
        if isinstance(j, dict):
            cmds = [c for c in map(command_line, iter_dicts(j)) if c]
            for c in cmds:
                self.runs += [(rel, "command", p) for p in node_scripts(c)]
            loader = next(filter(None, map(loader_reason, cmds)), None)
            if loader:
                self.add("DANGER", "ai-agent-config", rel, "AI-agent config runs a disguised file/download: " + loader)
                return
            # read in-repo scripts that hooks/servers call (e.g. "$CLAUDE_PROJECT_DIR/.claude/hooks/x.sh")
            bodies = []
            for ref in {r for c in cmds for r in AGENT_SCRIPT_RE.findall(c)}:
                src = self.resolve(ref)
                blob = read_sample(os.path.join(self.root, src)) if src else None
                if blob:
                    bodies.append((ref, decode(blob.data)))
            for ref, body in bodies:
                if marker_hits(body) or loader_reason(body, freeform=True):
                    self.add("DANGER", "ai-agent-config", rel, f"AI-agent hook script {ref} runs a malware loader")
                    return
            for what in cmds + [b for _, b in bodies]:
                if STEAL_SRC_RE.search(what) and STEAL_NET_RE.search(what):
                    self.add("DANGER", "ai-agent-config", rel, "AI-agent hook reads your keys/credentials and sends them over the network")
                    return
            bad = [c for c in cmds if AGENT_EXEC_RE.search(c)] + [f"{r}: {AGENT_EXEC_RE.search(b).group(0)}" for r, b in bodies if AGENT_EXEC_RE.search(b)]
            if bad:
                reasons.append("hook/server runs risky shell code (" + bad[0][:70] + ")")
            perms = as_dict(j.get("permissions"))
            if any(a in ("Bash", "Bash(*)", "Bash(*:*)") for a in as_list(perms.get("allow"))) or perms.get("defaultMode") == "bypassPermissions":
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
            self.add("WARNING", "ai-instructions", rel, "; ".join(reasons) + " - review before letting an AI agent work in this repo")

    def lockfile(self, rel, text):
        # names appear as "node_modules/<name>", "<name>": , <name>@<version>, '<name>@ - never as part of another name
        hits = sorted(npm_names_in(text))
        if hits:
            self.add("DANGER", "malicious-package", rel, "lockfile installs known malicious package: " + ", ".join(hits[:3]))

    def vscode(self, rel, low, text):
        if low == "tasks.json":
            tasks = folder_open_tasks(text)
            freeform = tasks is None
            if freeform:   # couldn't parse: judge the whole file
                tasks = [(text, bool(HIDDEN_TASK_RE.search(text)))] if FOLDER_OPEN_RE.search(text) else []
            if not tasks:
                return
            if marker_hits(text):
                self.autorun_tasks = True
                self.add("DANGER", "vscode-autorun", rel, "auto-run task contains known malware indicators")
                return
            for cmd, _ in tasks:
                self.runs += [(rel, "auto-run task", p) for p in node_scripts(cmd)]
            reason = next(filter(None, (loader_reason(cmd, freeform) for cmd, _ in tasks)), None)
            if reason:
                self.autorun_tasks = True
                self.add("DANGER", "vscode-autorun", rel, "task auto-runs a disguised file/download when the folder opens: " + reason)
            elif any(hidden for _, hidden in tasks):
                self.add("WARNING", "vscode-autorun", rel, "hidden task runs automatically on folder open - check what it runs")
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
        j = load_json(text)
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
        scripts = as_dict(j.get("scripts"))
        for k in LIFECYCLE:
            v = scripts.get(k)
            if isinstance(v, str):
                if LIFECYCLE_DANGER_RE.search(v):
                    self.add("DANGER", "install-script", rel, f'"{k}" downloads and runs code: {v[:70]}')
                elif re.search(r"\bnode\s+-e\b.*(?:https?://|eval|Buffer\.from|atob)", v):
                    self.add("WARNING", "install-script", rel, f'"{k}" runs inline code: {v[:70]}')
        for k, v in scripts.items():
            if isinstance(v, str):
                self.runs += [(rel, f'"{k}"', p) for p in node_scripts(v)]

    def finish(self):
        for rel, text in self.pending_settings:
            auto, trust_off, autorun = settings_risks(text)
            reasons = [r for r, on in (("turns on automatic tasks", auto), ("disables workspace trust", trust_off)) if on]
            if autorun and (auto or any(loader_reason(c, freeform=c is text) for c in autorun)):
                self.add("DANGER", "vscode-settings", rel, "turns on automatic tasks and hides an auto-run task inside settings")
            elif reasons:
                sev = "DANGER" if self.autorun_tasks else "WARNING"
                self.add(sev, "vscode-settings", rel, ", ".join(reasons))
        self.check_runs()
        for rel, data in self.configbat_files:
            if self.gitignore_configbat or BAT_PUSH_RE.search(decode(data)):
                self.add("DANGER", "worm-script", rel, "worm orchestrator batch file")

    def check_runs(self):
        """Files that tasks, agent hooks and package.json scripts run with node. A script that isn't a script (an
        image, a font, a data file) holding code is a disguised payload, whatever its extension; and whatever runs
        an infected file is part of the infection."""
        resolved = []
        for src, label, ref in self.runs:
            base = src.rsplit("/", 1)[0] if src.endswith("package.json") and "/" in src else ""
            target = self.resolve(ref, base)
            if target:
                resolved.append((src, label, target))
        for _, _, target in resolved:
            if target not in self.flagged and disguised(target):
                blob = read_sample(os.path.join(self.root, target))
                if blob and looks_like_code(blob.data):
                    self.add("DANGER", "disguised-payload", target,
                             f"is run as code but disguised as {os.path.splitext(target)[1] or 'a data file'}")
        for src, label, target in resolved:
            if target in self.flagged and src not in self.flagged and src.endswith("package.json"):
                self.add("DANGER", "script-chain", src, f"{label} runs the infected {target}")


def summary(code, findings, error=""):
    """One line for shell scripts, so none of them has to parse JSON (or guess what a missing result means)."""
    return f"{code} " + ("; ".join(f"{rel}: {detail}" for _, _, rel, detail in findings[:3]) or error)


def main(argv):
    if "--version" in argv:
        print("checkrepo", VERSION, "+ detection feed #%s (%s)" % (FEED["sequence"], FEED["published"]) if FEED else "(built-in indicators only)")
        return EXIT_CLEAN
    if "--help" in argv or "-h" in argv:
        print(__doc__)
        return EXIT_CLEAN
    if os.name == "nt":
        os.system("")  # enables ANSI colours in Windows terminals
    for stream in (sys.stdout, sys.stderr):
        try:   # never crash on emoji when output goes to a pipe with a legacy code page
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    quiet = "--quiet" in argv
    as_json = "--json" in argv
    as_summary = "--summary" in argv
    args = [a for a in argv if not a.startswith("--")]
    root = os.path.abspath(args[0] if args else ".")
    if not os.path.isdir(root):
        print(f"checkrepo: '{root}' is not a folder", file=sys.stderr)
        return EXIT_USAGE
    try:
        s = Scan(root, "--include-deps" in argv, "--all-files" in argv)
        s.walk()
    except Exception as e:     # a scanner bug must never look like "clean" (0) or "malware found" (1)
        msg = f"checkrepo: the scan could not finish ({e.__class__.__name__}: {e})"
        if as_json:
            print(json.dumps({"root": root, "exit": EXIT_ERROR, "error": msg, "findings": []}))
        else:
            print(summary(EXIT_ERROR, [], msg) if as_summary else msg, file=sys.stdout if as_summary else sys.stderr)
        return EXIT_ERROR
    danger = [f for f in s.findings if f[0] == "DANGER"]
    warn = [f for f in s.findings if f[0] == "WARNING"]
    code = EXIT_DANGER if danger else (EXIT_WARNING if warn else EXIT_CLEAN)
    if as_json:
        print(json.dumps({"root": root, "exit": code, "findings": s.findings,
                          "feed": {"sequence": FEED["sequence"], "published": FEED["published"]} if FEED else None}))
        return code
    if as_summary:
        print(summary(code, danger + warn))
        return code
    tty = sys.stdout.isatty() or os.environ.get("CHECKREPO_COLOR") == "1"
    R, Y, G, D, X = ("\033[1;31m", "\033[1;33m", "\033[1;32m", "\033[2m", "\033[0m") if tty else ("",) * 5
    if not s.findings:
        if not quiet:
            print(f"{G}✅ checkrepo: no signs of malware found{X} {D}({root}){X}")
        return code
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
        print(f"\n  What to do: see docs/after-a-scan/if-danger-found.md in Ardvane (cut off access first, then clean).")
        print(f"  Sure it's a false alarm? Allow that exact file: add its SHA-256 to ~/.config/checkrepo/allowlist")
    print()
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
