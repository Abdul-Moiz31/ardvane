# checkrepo — scanner, git hooks and safe clone

`checkrepo` is a small, dependency-free Python scanner that looks for the tricks used by the
PolinRider / Contagious Interview / TasksJacker / GlassWorm campaigns. It **only reads files** — it never runs
anything from the folder it scans, so it is safe to point at an infected project.

## Install

| | Command | Status |
|---|---|---|
| **macOS / Linux** | `bash mac/install.sh` (preview first with `--dry-run`) | ✅ tested |
| **Windows** | `powershell -ExecutionPolicy Bypass -File windows\install.ps1` (preview with `-DryRun`) | 🧪 beta — written carefully but not yet tested on real Windows. Please report results in Issues. |

Requirements: `git` and Python 3.8+. Open a **new terminal** afterwards and run `checkrepo --version`.

Undo everything (scanner, hooks, safe clone and the daily routine):
`bash mac/uninstall.sh` · `powershell -ExecutionPolicy Bypass -File windows\uninstall.ps1`

Installer options: `--dry-run` / `-DryRun` (preview), `--no-npm`, `--no-editor`, `--no-safeclone`,
`--force-hooks` (replace an existing global hooks folder — the old value is saved and restored on uninstall).

## What gets installed

| Piece | What it does |
|---|---|
| `checkrepo` command | Scan any folder: `checkrepo ~/Downloads/some-project` |
| Global git hooks (`core.hooksPath`) | **After** `git clone` / `pull` / `checkout`: scans and warns. **Before** `git push`: blocks the push if malware is found, so it can't spread from your machine. Then hands over to the repo's own hooks, so they keep working. |
| Safe clone (`git clone` in your terminal) | Downloads the repo **without writing project files**, scans a private copy, and only writes the files if clean. If malware is found the clone is **blocked** and the download goes to the Trash / Recycle Bin. |
| npm hardening | `ignore-scripts=true` — packages can't run install scripts on your machine. Per trusted project, if needed: `npm install --ignore-scripts=false` |
| Editor hardening (VS Code / Cursor / Windsurf) | Automatic tasks **off**, Workspace Trust **on** — opening a folder can't silently run code. |

The installer never overwrites an existing global hooks setup without `--force-hooks`, backs up every file
it edits (`*.bak-checkrepo`), skips editor settings files that contain comments (and tells you what to add),
and is safe to run again.

## What it detects

| Severity | Meaning | Effect with the git hooks |
|---|---|---|
| 🛑 **DANGER** | Specific evidence of the campaign | Blocks safe-clone and push |
| ⚠️ **WARNING** | Unusual, but can be legitimate — worth a look | Shown, never blocks |
| ✅ clean | Nothing found | Silent |

Rules (each is covered by the self-test in `tests/`):

1. **Hidden code** — code appended after a long run of spaces at the end of a line, starting with the
   campaign's loader openings (`global['!']=…`, `global.i = 'A11'`, `function _0x…`). Real samples used 149–776 spaces.
2. **Fake fonts** — `.woff2/.woff/.ttf/.otf/.eot/.llf` files that don't start with real font bytes and contain JavaScript.
   (Git LFS pointer files and real fonts are recognised and ignored.)
3. **Auto-run VS Code tasks** — a task in `.vscode/tasks.json` that runs on folder open (`"runOn": "folderOpen"`)
   **and** whose own command runs a loader: `node` on a font or data file (`.woff2/.woff/.eot/.ttf/.otf/.llf/.fnt/.dict`)
   or a `fonts/` folder, `curl … | sh`, PowerShell `iwr … | iex`, or the `command -v node … || where node >nul` fingerprint,
   or contains a known campaign host. Only folder-open tasks are judged (other tasks in the file are ignored);
   `tasks.json` comments are understood. A hidden folder-open task without a loader is a WARNING; a normal visible
   auto-start task (e.g. `npm run watch`) is ignored.
4. **VS Code settings** that turn on automatic tasks together with a hidden auto-run task.
5. **Known campaign markers** — obfuscator strings, XOR keys, blockchain dead-drop wallets, C2 hosts and IPs
   (IPs only match as standalone addresses, never inside version numbers), exact SHA-256 fingerprints of known payloads.
6. **Worm traces** — `temp_auto_push.bat`, `temp_interactive_push.bat`, a `.gitignore` hiding them, a `config.bat` that pushes.
7. **Malicious packages** — 84+ known-bad npm names in `package.json` (including `npm:` aliases) **and lockfiles**
   (npm, pnpm incl. v6, yarn, bun; up to 50 MB). Look-alikes such as `tailwind-merge` are not matched.
8. **Install scripts** that download and run code (`curl … | sh`, PowerShell `iwr | iex`, `base64 -d | sh`).
9. **Oct 2026 variant** — a root-level `api.js` holding a hex-string-array loader on one huge line.
10. **Implant file names** — `MicrosoftSystem64*`, `SvcHostUpdate.py/.js`, `MicrosoftCLROptimization.vbs`, `fa-solid-NNN.llf`.
11. **GlassWorm-style invisible code** — long runs of invisible Unicode characters (variation selectors / tag characters) hiding encoded code.
12. **AI coding-agent traps** — `.claude/settings.json` hooks and `.mcp.json` servers that run loaders or read your SSH/AWS keys and send them out
    (the scanner also reads the in-repo scripts those hooks call), hidden invisible-Unicode instructions in `CLAUDE.md` / `AGENTS.md` / `.cursorrules`,
    and API-URL overrides that could leak your AI API keys.

In a git repository it scans what the repo contains (tracked files + new non-ignored files — including anything
committed inside `node_modules`), skipping build output that git ignores — typically 0.1–0.7 s per repo. Any other
folder (e.g. an unzipped download) is scanned fully. It runs git with `core.fsmonitor` and hooks disabled, so a
booby-trapped `.git/config` in a scanned folder can't make it run anything.

## If it says DANGER

1. **Don't open** the folder in VS Code / Cursor and **don't run** `npm install` or any script in it.
2. If it was a clone, the safe clone already blocked it and moved the download to the Trash / Recycle Bin (or `~/.checkrepo/quarantine`).
3. If it's one of **your** repositories, follow [`after-a-scan/if-danger-found.md`](after-a-scan/if-danger-found.md) — cut off access first, then clean.

## Accuracy

Measured during development (see the main README for the full method):

| Test | Result |
|---|---|
| Real malware files from an actual infection (71 unique samples, both payload variants) | **71 / 71 detected** |
| Same samples with every known marker and fingerprint switched off (behaviour rules only) | **71 / 71 detected** |
| 18 popular open-source projects (106,225 files: Font-Awesome, Babel, Webpack, Prettier, ESLint, Vite, Jest, javascript-obfuscator, VS Code samples…) | **0 false alarms** |
| A developer's own 14 projects including all installed packages (~240,000 files) | **0 false alarms**, 1 real leftover found |
| Built-in self-test (`python3 scanner/tests/run_tests.py`) | 51 cases: must-catch, must-warn, must-stay-quiet, plus security and consistency checks |

## Limits — please read

- It is built for **this family of attacks**. A completely new technique may not be detected — that's why the
  kit also hardens your editor, npm and git, and why the daily routine exists.
- The automatic scan doesn't run in repos that use **Husky / lefthook** (they replace the hooks folder). The daily routine still scans them.
- Clones made with **GUI buttons** (VS Code "Clone Repository", GitHub Desktop) get the after-clone warning, not the block.
- Malware already running on your machine can skip git hooks. Combine the kit with the account protections in
  [`after-a-scan/hardening-checklist.md`](after-a-scan/hardening-checklist.md).
- With `--recurse-submodules`, submodules are scanned after they are fetched (and the clone is moved away if one is infected).

## Compatibility notes

- **Global hooks folder:** tools that install hooks into `.git/hooks` keep working (the kit hands over to them),
  but the Python **`pre-commit` framework refuses to install** while a global `core.hooksPath` is set, and
  **Git LFS** can't add its hooks automatically. Run `git config --global --unset core.hooksPath` temporarily,
  install them (`pre-commit install`, `git lfs install`), then re-run the kit's installer to turn the global hooks back on.
- **npm `ignore-scripts`** also skips the `pre`/`post` steps of `npm run` (e.g. `prebuild`). For a trusted project:
  `npm install --ignore-scripts=false`, or put `ignore-scripts=false` in that project's `.npmrc`.
- **Safe clone covers `git clone` typed in a terminal** (zsh, bash, PowerShell, Git Bash). `gh repo clone`, GUI
  buttons and cmd.exe aren't wrapped — the post-clone hook still scans and warns. If you have your own shell
  alias named `git`, your alias wins and safe clone stays off.

## False alarm?

`git push --no-verify` (push) or `command git clone …` / `git.exe clone …` (clone) skip the check once.
To permanently allow one specific file, add its SHA-256 to `~/.config/checkrepo/allowlist`
(`shasum -a 256 <file>` / `Get-FileHash <file>`). It is allowed by exact content, so if the file changes it is checked again.
Please also open an issue so the rule can be improved.
