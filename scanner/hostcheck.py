#!/usr/bin/env python3
"""hostcheck - machine checks the scan and the daily check share (macOS and Linux). Read-only.

Part of Ardvane (MIT). Python 3.8+, standard library only.

  python3 hostcheck.py            one finding per line:  D|W|I <tab> message <tab> path
  python3 hostcheck.py --json     the same as JSON

What it checks, beyond the scripts' own checks:
  * every known malware location in lists/malware-paths.txt for this system (one list, also used by the fixer);
  * worm persistence: self-hosted GitHub runners registered by Sha1-Hulud, sabotage lines in shell start-up files,
    a git template folder set by SANDWORM_MODE;
  * AI coding-agent configs in your home folder (Claude Code, Claude Desktop, Cursor, Windsurf, Gemini, VS Code):
    hooks and MCP servers that run loaders, steal keys, or run code hidden in a dot-folder;
  * editor extensions: known-malicious ones and GlassWorm-style invisible code.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kitlib  # noqa: E402

HOME = kitlib.HOME
IS_MAC = kitlib.IS_MAC

# Wipers that erase your home folder when you revoke the token they stole: remove them BEFORE rotating tokens
WIPERS = ("gh-token-monitor", "kitty-monitor")
# Extensions known to be malicious (publisher.name, optionally @version when only one release was hijacked)
BAD_EXTENSIONS = {
    "nrwl.angular-console@18.95.0",                    # Nx Console, May 2026 (stolen publisher token)
    "specstudio.code-wakatime-activity-tracker",       # GlassWorm Zig dropper, Apr 2026
    "floktokbok.autoimport",                           # GlassWorm Zig dropper, Apr 2026
}
# Shell start-up lines that sabotage the machine (s1ngularity appended `sudo shutdown -h 0`)
SABOTAGE_RE = re.compile(r"^\s*(?:sudo\s+)?shutdown\s+-h\s+(?:0|now)\b|^\s*(?:sudo\s+)?rm\s+-rf\s+(?:~|\$HOME)/?\s*$", re.M)
SHELL_FILES = (".zshrc", ".zprofile", ".zshenv", ".bash_profile", ".bashrc", ".profile")
# Dot-folders in your home that legitimately hold tools an MCP server or hook may run
TOOL_DIRS = {".npm", ".nvm", ".volta", ".bun", ".deno", ".cargo", ".local", ".pyenv", ".rbenv", ".asdf", ".sdkman", ".fnm",
             ".claude", ".cursor", ".codeium", ".vscode", ".config", ".docker", ".orbstack", ".rd", ".gem", ".pnpm", ".yarn"}


def agent_configs():
    """AI coding-agent config files in your home folder that start commands."""
    sup = os.path.join(HOME, "Library", "Application Support") if IS_MAC else os.path.join(HOME, ".config")
    return [os.path.join(HOME, p) for p in (".claude/settings.json", ".claude/settings.local.json", ".claude.json",
                                            ".cursor/mcp.json", ".codeium/windsurf/mcp_config.json", ".gemini/settings.json")] \
        + [os.path.join(sup, p) for p in ("Claude/claude_desktop_config.json", "Code/User/mcp.json", "Cursor/User/mcp.json")]


def hidden_home_dir(path):
    """The dot-folder in your home a command runs from (`~/.dev-utils/x.js` -> `.dev-utils`), unless it is a tool folder."""
    p = path.replace("$HOME", HOME).replace("~", HOME, 1) if path.startswith(("~", "$HOME")) else path
    if not p.startswith(HOME + os.sep):
        return None
    first = p[len(HOME) + 1:].split(os.sep, 1)[0]
    return first if first.startswith(".") and first not in TOOL_DIRS else None


def check_agent_configs(cr, out):
    for path in agent_configs():
        blob = cr.read_sample(path, 20 * cr.MB)
        if not blob:
            continue
        text = cr.decode(blob.data)
        s = cr.Scan(os.path.dirname(path))
        s.allow = set()
        s.agent_config(os.path.basename(path), text)
        shown = path.replace(HOME, "~", 1)
        for sev, _, _, detail in s.findings:
            out.append(("D" if sev == "DANGER" else "W", f"{shown}: {detail}", path))
        if any(sev == "DANGER" for sev, *_ in s.findings):
            continue
        j = cr.load_json(text, jsonc=True)
        for d in cr.iter_dicts(j):
            cmd = cr.command_line(d)
            if not cmd:
                continue
            hidden = next(filter(None, (hidden_home_dir(w.strip("\"'")) for w in cmd.split())), None)
            if hidden:
                out.append(("W", f"{shown}: an AI agent runs a program from the hidden folder ~/{hidden} - "
                                 f"worms install their MCP servers there; remove it unless you added it ({cmd.replace(HOME, '~')[:80]})", path))
                break
            if re.search(r"\bnpx\b[^\n]*\bgithub:", cmd):
                out.append(("W", f"{shown}: an AI agent runs code straight from a GitHub repository ({cmd[:80]}) - check you added it", path))
                break


def check_runners(out):
    """Sha1-Hulud registers your computer as a self-hosted GitHub Actions runner named SHA1HULUD (in ~/.dev-env)."""
    seen = set()
    for base in (HOME, os.path.join(HOME, ".dev-env")):
        try:
            names = os.listdir(base)
        except OSError:
            continue
        for name in names:
            runner = os.path.join(base, name, ".runner") if name != ".runner" else os.path.join(base, ".runner")
            if runner in seen:
                continue
            seen.add(runner)
            data = kitlib.read_json(runner, {}) if os.path.isfile(runner) else None
            if data:
                label = str(data.get("agentName", ""))
                where = os.path.dirname(runner).replace(HOME, "~", 1)
                if "hulud" in label.lower():
                    out.append(("D", f"this computer is registered as a GitHub runner named {label} by the Sha1-Hulud worm: {where}", os.path.dirname(runner)))
                elif os.path.relpath(os.path.dirname(runner), HOME).split(os.sep)[0].startswith("."):
                    out.append(("W", f"a GitHub Actions runner is installed in a hidden folder ({where}, runner {label}) - remove it unless you set it up", os.path.dirname(runner)))


def check_shell_files(out):
    for name in SHELL_FILES:
        path = os.path.join(HOME, name)
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read(1_000_000)
        except OSError:
            continue
        m = SABOTAGE_RE.search(text)
        if m:
            out.append(("D", f"~/{name} shuts down or wipes this computer every time a terminal opens ({m.group(0).strip()}) - "
                             "the nx s1ngularity malware added this", path))


def git_global(key):
    try:
        r = subprocess.run(["git", "config", "--global", "--get", key], capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def check_git(out):
    tdir = git_global("init.templateDir")
    if tdir:
        out.append(("W", f"git copies files from {tdir} into every repository you create or clone (init.templateDir) - "
                         "worms use this to plant hooks; remove it unless you set it: git config --global --unset init.templateDir", ""))


def check_extensions(cr, out):
    for root in (".vscode/extensions", ".cursor/extensions", ".windsurf/extensions", ".vscode-insiders/extensions"):
        folder = os.path.join(HOME, root)
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        for name in names:
            ext = os.path.join(folder, name)
            manifest = kitlib.read_json(os.path.join(ext, "package.json"), {})
            if not manifest:
                continue
            ident = f"{manifest.get('publisher', '')}.{manifest.get('name', '')}".lower()
            version = str(manifest.get("version", ""))
            if ident in BAD_EXTENSIONS or f"{ident}@{version}" in BAD_EXTENSIONS:
                out.append(("D", f"known malicious editor extension installed: {ident} {version} ({root})", ext))
                continue
            # GlassWorm: code encoded in invisible Unicode in the extension's own scripts
            for dp, dns, fns in os.walk(ext):
                dns[:] = [d for d in dns if d not in ("node_modules", ".git")] if dp == ext else [d for d in dns if d != ".git"]
                if dp.count(os.sep) - ext.count(os.sep) > 2:
                    dns[:] = []
                hit = None
                for fn in fns:
                    if fn.endswith((".js", ".cjs", ".mjs")):
                        blob = cr.read_sample(os.path.join(dp, fn), 3 * cr.MB)
                        if blob and cr.INVISIBLE_RUN_RE.search(cr.decode(blob.data)):
                            hit = os.path.join(dp, fn)
                            break
                if hit:
                    out.append(("D", f"editor extension {ident} hides code in invisible Unicode (GlassWorm): {hit.replace(HOME, '~', 1)}", ext))
                    break


# Credentials kept in plain files - the first thing every stealer and worm copies. Values are never read out or shown:
# only whether a file holds one. (file, what it is, test on the file's text, safer place)
PLAIN_SECRETS = (
    (".npmrc", "npm token", re.compile(r"_authToken\s*=\s*(?!\$\{)\S{8,}"), "use a short-lived granular token, or `npm login` per session"),
    (".git-credentials", "git passwords / tokens", re.compile(r"https?://[^:\s]+:[^@\s]{8,}@"), "use the system keychain: git config --global credential.helper osxkeychain (or manager on Windows)"),
    (".config/gh/hosts.yml", "GitHub CLI token", re.compile(r"oauth_token:\s*\S{8,}"), "run `gh auth logout` then `gh auth login`: it then keeps the token in the system keychain"),
    (".aws/credentials", "AWS secret key", re.compile(r"aws_secret_access_key\s*=\s*\S{16,}"), "use AWS SSO (`aws configure sso`) or short-lived credentials"),
    (".docker/config.json", "registry password", re.compile(r'"auth"\s*:\s*"[A-Za-z0-9+/=]{12,}"'), "use a credential helper (\"credsStore\": \"osxkeychain\" / \"desktop\")"),
    (".pypirc", "PyPI password / token", re.compile(r"^\s*password\s*[:=]\s*\S{8,}", re.M), "use trusted publishing or keyring"),
    (".netrc", "machine password", re.compile(r"\bpassword\s+\S{6,}"), "remove passwords you no longer need"),
)


def check_secrets(out):
    """Which credentials sit in plain files a stealer would copy. A list to protect - and to rotate after an infection."""
    for rel, what, rx, better in PLAIN_SECRETS:
        path = os.path.join(HOME, *rel.split("/"))
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read(1_000_000)
        except OSError:
            continue
        if rx.search(text):
            out.append(("W", f"{what} stored in plain text in ~/{rel} - stealers copy this file first; {better}", path))


def check_paths(out):
    """Known malware locations from the shared list (the fixer can quarantine every one of them)."""
    spec = importlib.util.spec_from_file_location("autofix", kitlib.find("autofix.py"))
    af = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(af)
    for path, _ in af.known_paths():
        if os.path.lexists(path):
            shown = path.replace(HOME, "~", 1)
            if any(w in path for w in WIPERS):
                out.append(("D", f"found: {shown} - a wiper that ERASES YOUR HOME FOLDER if you revoke the GitHub token it stole. "
                                 "Quarantine it first (Ardvane can), and only then rotate your tokens", path))
            else:
                out.append(("D", f"found: {shown}", path))


# check -> the scan report section its findings belong to (the scripts print each group in its own section)
CHECKS = ((check_paths, "malware", False), (check_runners, "malware", False), (check_shell_files, "shell", False),
          (check_git, "shell", False), (check_agent_configs, "editors", True), (check_extensions, "editors", True),
          (check_secrets, "protections", False))


def run_all():
    cr = kitlib.load_checkrepo()
    out = []
    for check, group, needs_cr in CHECKS:
        found = []
        try:
            check(cr, found) if needs_cr else check(found)
        except Exception as e:          # one broken check must not hide the others
            found.append(("W", f"a machine check could not finish ({check.__name__}: {e.__class__.__name__})", ""))
        out += [(lvl, text, path, group) for lvl, text, path in found]
    return out


def main(argv):
    found = run_all()
    if "--json" in argv:
        print(json.dumps([{"level": lvl, "text": t, "path": p, "group": g} for lvl, t, p, g in found]))
    else:
        for lvl, text, path, group in found:
            print("\t".join(x.replace("\t", " ").replace("\n", " ") for x in (lvl, text, path, group)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
