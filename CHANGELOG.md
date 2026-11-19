# Changelog

Each version's section becomes its GitHub release notes automatically. To release, raise `VERSION` in
`app/backend/config.py`, add a section here, and merge the pull request.

## 0.8.0

- **Secrets committed to your repositories.** GitHub, npm, AWS, OpenAI, Anthropic, Slack, Stripe and PyPI keys and
  private keys in the files a repository would share, and `.env` files that aren't git-ignored. Only formats that can't
  be anything else count, placeholders are ignored, and git-ignored files are never reported. Shown as "worth a look",
  with the steps to revoke the key and remove it from history.
- **Credentials in plain files on this computer:** npm, GitHub CLI, AWS, Docker, PyPI, git and netrc credentials kept
  in files that stealers copy first, with the safer place for each. Their values are never read out or shown. After
  an infection, this is your list of what to rotate.
- **Worm traces in your GitHub account:** repositories the Shai-Hulud worms create to publish stolen secrets
  ("Sha1-Hulud: The Second Coming.", "Shai-Hulud: Here We Go Again.", `s1ngularity-repository`) are reported as
  DANGER by the GitHub check.
- **Fewer false alarms:** the `.pth` files every virtualenv and setuptools install creates are no longer reported;
  a `.pth` that runs hidden code is still caught, also inside a project's own `.venv`.

## 0.7.0

- **A new look for the dashboard: "Midnight".** Chosen from three directions inspired by Motion (Framer Motion), the
  tools developers already use, and the security apps in this space. Near-black surfaces, bold headlines, monospace
  labels and numbers, and one electric-lime accent for the things you act on. The verdict is a big headline with a
  status ring in its colour, which sweeps while a scan runs.
- **Light mode** keeps the same design on near-white, with a deeper lime so everything stays readable. Auto follows
  your computer.
- **Motion that feels physical**: pages spring in when you open them, lists and chart bars follow in sequence, numbers
  count up, buttons and toggles respond with a spring. It's Framer Motion's spring, computed in the browser - no
  library, no download - and it turns off when your system asks for reduced motion.

## 0.6.0

**Ardvane can now clean up what it finds, on its own if you let it.**

- **New fix mode: "Automatic: remove malware too"** (Settings → Fixes). As soon as a scan or the daily check finds
  malware, Ardvane stops malware processes, quarantines malware files, loose scripts and malicious editor extensions,
  removes the shutdown line malware adds to shell start-up files, and cleans infected projects.
- **Infected projects are cleaned, not moved away.** Only the malicious parts go: the code hidden after spaces in a
  build config, fake fonts and payload files, the worm's `.gitignore` lines and install scripts, invisible instructions in
  AI-agent files, malicious tasks, hooks and workflows. Your own code, settings and dependencies stay exactly as they
  were. The same cleanups are offered as **Fix…** buttons in "Ask me" mode.
- **Nothing is deleted, everything can be undone.** Quarantined files and the original of every edited file are kept
  in `~/.checkrepo/quarantine`, and each fix is checked afterwards. Moving a whole project, anything on GitHub and
  rotating secrets still wait for you.

## 0.5.0

**Ardvane now finds the 2025–2026 worms on the computer itself, and removes their wipers safely.**

- **Worm persistence:** the `gh-token-monitor` and `kitty-monitor` wipers, a GitHub Actions runner registered by
  Sha1-Hulud, SANDWORM_MODE's MCP folder and git template, the OtterCookie lock file, shell start-up lines that shut the
  computer down, and the worms' running processes. Every known malware location now comes from one list, which is also
  what the fixer quarantines.
- **The wipers erase your home folder when you revoke the token they stole.** Ardvane's to-do, recovery checklist and
  guide now tell you to quarantine them first; the fixer stops them before moving them.
- **AI coding assistants and editors on this computer:** hooks and MCP servers in your Claude Code, Claude Desktop,
  Cursor, Windsurf, Gemini and VS Code configs that run malware loaders, steal keys, or run from a hidden folder or
  straight from GitHub; known-malicious editor extensions and GlassWorm code hidden inside extensions.
- **A quieter daily check.** An updated startup item signed by an identified developer (Malwarebytes, say) is noted
  instead of becoming a to-do, an extension update no longer counts as a new extension, and warnings about a state that
  is fixed now close themselves.
- **Folders macOS keeps background jobs out of** (Documents, Desktop, Downloads) are named on the Overview with a
  **Scan them now** button, instead of the advice to give `/bin/bash` Full Disk Access.

## 0.4.0

**Ardvane now catches the self-spreading npm worms of 2025–2026 and reads many more places code can hide.**

- **Shai-Hulud and its successors** (Sha1-Hulud 2.0, Mini Shai-Hulud, ChainDrop): their payload and wiper file names and
  fingerprints, install scripts that run their loaders, and any script that runs on its own (install script, AI-agent hook,
  folder-open task, git hook, dev container) and is obfuscated, downloads the Bun runtime to run a payload, or is a large
  minified bundle hunting for tokens.
- **Hijacked releases** of popular packages: axios 1.14.1 / 0.30.4, the September 2025 chalk / debug releases, the nx
  "s1ngularity" releases, litellm and telnyx. Found in `package.json` pins and in npm, yarn, pnpm, bun and Python lockfiles.
- **GitHub Actions workflows** are read for the first time: backdoor workflows on self-hosted runners, secret dumps,
  runner-memory theft, and warnings for command injection and `pull_request_target` running a PR's own code.
- **AI coding assistants abused by malware**: install scripts that start `claude --dangerously-skip-permissions`,
  `gemini --yolo` or `q --trust-all-tools`. More agent files are read (Cursor rules in subfolders, Windsurf, Cline,
  Copilot instructions and prompts, Claude commands, agents and skills, Kiro, Amazon Q, Roo, Continue), and settings that
  approve a repository's MCP servers or AI tools without asking are reported.
- **Contagious Interview loaders**: code that fetches its next stage from JSON storage sites, or decodes data hidden in
  SVG images, and runs it.
- **Code that runs without being called**: Python `.pth` files, git hooks a repository ships (Husky, lefthook,
  `.githooks`, pre-commit), Dev Container commands that run on your computer, tasks a folder-open task depends on, and
  JavaScript inside `.vscode/`.
- **Malicious Python packages** are now caught by the git hooks, safe clone and the GitHub Action too, not only by the
  machine scan. New npm and PyPI names from 2026 reports were added.
- **Project folders can be added and removed again.** Settings → What gets scanned failed with "folder not found" on any
  computer without one of the default folders, so no change could be saved; "Reset to defaults" and "My project folders"
  scans failed the same way. Missing folders are now marked and skipped, every spelling of a folder is one entry, and
  text you are typing is no longer wiped when the page refreshes.

## 0.3.3

- **Allow-listing a file now also clears the "disguised payload" alarm.** A script that a package.json script, task
  or agent hook runs from a `fonts/` folder was flagged as DANGER even after you added its SHA-256 to
  `~/.config/checkrepo/allowlist`, and its package.json was flagged as "script-chain" with it. That blocked clean
  pushes of projects such as docx-editor, whose `packages/fonts/` scripts are ordinary Node scripts. The allowlist
  now applies to this rule like every other. It still covers only that exact file: change one byte and it is flagged
  again, and a fake font run as code is still caught.

## 0.3.2

- **The app icon starts Ardvane natively on Apple Silicon Macs.** An app whose program is a script has no chip type,
  so macOS could start it under Rosetta, and everything Ardvane ran inherited that: "Update protection" then failed
  with `xcrun: … need 'x86_64'` because git couldn't load Apple's command line tools. The icon now asks macOS for
  native execution and starts Ardvane natively itself. **Re-create the icon once** (Protection → Ardvane app icon →
  Remove, then Add) to get the fixed one.

## 0.3.1

- **"Update protection" works when Ardvane is opened from its app icon.** macOS gives apps started from an icon a
  minimal PATH, so the installer couldn't find Python ("Python 3.8+ is required") even though Ardvane itself was
  running on it. The app now hands every script it starts the Python it runs on, the installer records it, and the
  daily check uses that recorded Python too, so machine scans and daily checks no longer skip project checks for the
  same reason. The message for a missing Python now gives the right fix.

## 0.3.0

**The scanner can't be talked out of a finding any more.** An October 2026 audit tried to sneak malware past it;
every way that worked is now caught, and covered by a test.

- A file that breaks the analysis (a malformed value, 100,000 nested brackets) is reported as "could not be analysed"
  instead of stopping the scan. A scanner failure exits with code 4 and is shown as "could not scan" - never as clean,
  and never as malware.
- Linked `.vscode` / `.claude` folders and config files are read through the link. Files git ignores are still scanned
  where editors and AI agents read them (`.vscode`, `.claude`, MCP files, config files, fonts).
- Fake fonts are recognised by their structure, not just their first bytes: a file starting with `true;`, padded with
  non-English text or bigger than 2 MB no longer passes as a font.
- Files too large to read fully are checked at both ends, and big config files are reported instead of skipped.
- Anything run with `node` that isn't a script (an image, a data file, a preload) is checked as code. Code hidden after
  line breaks or non-standard spaces, `.VSCode` folders, JSON escapes such as `folder\u004fpen`, comments in MCP
  config and AI-agent status-line commands are all caught.
- Named pipes no longer hang a scan.
- Safe clone now scans committed `node_modules` / `.venv` folders too, and prints the right command for a false alarm.
- New `checkrepo --summary` for scripts. No new false alarms on 90,000 real project files.

**Git protection checks what you push, and notices when it is switched off.**

- `git push` scans the commits being pushed, not the folder you happen to have open: an infected branch is blocked
  even while a clean branch is checked out, and untracked files no longer block unrelated pushes. Your own pre-push
  hooks still receive the list of refs.
- The daily check now notices protection being turned off from an `[include]`/`[includeIf]` file, a git hook replaced
  or removed, a protection file deleted, a repository switching hooks off for itself (Husky folders are fine), and
  the shell setup being removed.

**Scan any GitHub repository, not only your account.**

- **Settings → GitHub → Repositories to scan:** add repositories one by one (yours, your organization's, a
  teammate's) as `owner/name`, a github.com link or a `git@github.com:` address, and remove them like folders. Every
  branch of each one is scanned with each scan and daily check. A repository that can't be checked shows as a
  warning, never as clean.
- `ardvane check-github owner/name` scans every branch of repositories from the terminal, without cloning them.
- Settings changes are saved one at a time and lists change by "add" / "remove", so quick clicks or a second tab can
  no longer lose a change.

**A GitHub Action: the scanner on GitHub's servers.**

- `uses: Abdul-Moiz31/ardvane@v0.3.0` scans every push and pull request: malware fails the check and shows up on the
  exact file. With `mode: all-branches` on a schedule it scans every branch through the GitHub API, plus any other
  repositories you list, such as your whole organization. See docs/github-action.md.
- Read-only, needs only `contents: read`, and file names from the scanned repository can't inject workflow commands.
  Ardvane's own CI runs the Action on itself.

**Safe install: malicious packages are stopped before they install.**

- `npm`, `npx`, `pnpm`, `yarn`, `bun` and `pip` now check every package an install would add - for npm the full
  dependency tree, worked out in a private copy of the project without running anything - against Ardvane's list and
  OSV.dev's database of malicious packages. A known-malicious package means nothing is installed.
- Only public package names are sent to OSV.dev (never private-registry packages), answers are cached, and the online
  check can be turned off under Settings → Detections. Everyday commands like `npm run dev` pass straight through, and
  a failure of the check never stops your package manager.
- One shell file holds the functions for macOS/Linux and Git Bash; PowerShell gets the same. The Protection page shows
  whether safe install is on.

**Detections that keep up between releases.**

- Before each scan and daily check, Ardvane downloads a signed list of new detections - attacker servers and IPs,
  malware fingerprints, code markers, malicious npm and PyPI packages - so it recognises new variants without an
  upgrade. Settings → Detections shows the list you have and can turn updates off; `ardvane update-detections` updates
  from the terminal.
- The list is used only with Ardvane's Ed25519 signature (verified by the app itself, no dependencies), only if newer
  than the copy you have, and it can only add detections. A failed update keeps the last good copy.
- Indicator matching now looks each finding up instead of trying every pattern, so a large list doesn't slow scans
  down; the package checker and the scanner share one implementation.

**Releases can't be faked.**

- Every release carries a reproducible source archive signed with GitHub's build provenance. Only the release
  workflow running on `main` can produce that signature, and the Homebrew tap now refuses any release without it -
  so a stolen token that creates a release or pushes a tag can't ship code to brew users.
- A release is refused if its version is older than the latest one, or if its tag already exists on another commit.
  PyPI is built from the release tag, releases never run twice at once, and every GitHub Action is pinned to an
  exact commit.

## 0.2.2

**The GitHub check now sees everything.** It used to stop at your first 100 repositories and skip repositories over
200 MB. A real infected 202 MB repository was missed that way.

- Every repository is listed, not just the first 100.
- No fixed size limit. Downloads are streamed to disk instead of memory, and stop only if less than 2 GB of disk space
  would be left (or after 30 minutes). Single files over 20 MB, such as videos or models, are listed as not scanned.
- New `--all-branches` option: the worm pushes into every branch, not only the main one.
- Harder to trick: files whose names differ only in upper/lower case are both scanned, one file with a name this
  computer can't store no longer stops the whole branch from being scanned, and oversized archives ("tar bombs")
  can't fill the disk.
- More reliable: GitHub's rate limit stops the check once with a clear message, timeouts and empty repositories no
  longer cause errors, and temporary folders left by an interrupted check are cleaned up.
- Scan reports are saved in `~/.checkrepo/reports/scans`, where the dashboard lists them, instead of inside the app's
  folder (which an upgrade replaces). The end of a scan now says `ardvane protect` instead of a script path.

## 0.2.1

- The "Ardvane has stopped" message now says how to reopen it: the app icon, or `ardvane` in Terminal.
- The dashboard waits 20 minutes (was 5) before closing itself, because browsers pause background tabs.
- "Add app icon" explains what it does: it adds Ardvane to your Applications folder (Start menu on Windows), so you
  can open it from Launchpad, Spotlight or the Dock.

## 0.2.0

**Install Ardvane with one command.** No cloning needed.

```bash
brew install abdul-moiz31/ardvane/ardvane     # macOS (Homebrew)
pipx install ardvane                          # macOS, Linux and Windows
```

Then run `ardvane` to open the dashboard.

- New terminal commands: `ardvane scan`, `ardvane check <folder>`, `ardvane protect`, `ardvane unprotect`,
  `ardvane fixes`, `ardvane launcher`. Run `ardvane --help` for all of them.
- Published to PyPI automatically with every release (trusted publishing, no stored passwords or tokens), and to
  Homebrew through the `abdul-moiz31/ardvane` tap, which follows releases by itself.
- The app icon now opens the installed `ardvane` command, so it keeps working after upgrades.

## 0.1.0

The first release of **Ardvane**: free, open-source protection for developers against malware that spreads through code
(fake job interviews, malicious packages and the PolinRider worm). Everything runs on your own computer.

**Get started**

```bash
git clone https://github.com/Abdul-Moiz31/ardvane.git
cd ardvane
python3 app/dashboard.py
```

**What's in 0.1.0**

- **Ardvane dashboard** — status at a glance, scans with live progress, 30-day history, protection switches, reports
  and offline guides. Runs on `127.0.0.1` only.
- **Scans your computer** — malware locations, running malware, startup items, attacker connections, editor settings,
  every git project and installed package.
- **Blocks infected code** — safe `git clone`, scans on pull / checkout, blocks infected pushes.
- **Hardening** — editors can't auto-run code from a folder; npm packages can't run install scripts.
- **Fixes with undo** — ask first (default) or automatic. Malware is quarantined, never deleted.
- **To-do list** — every finding becomes practical steps; a later scan checks your fix worked; weekly GitHub-account checks.
- **Daily check** at the time you choose, with a notification.
- **GitHub account check** (optional) — uses the GitHub CLI when you're logged in; your token stays there.

Platforms: macOS and Linux; Windows is beta. Requires Python 3.8+ and git, nothing else.
Found a false alarm or tested on Windows? Please open an issue.
