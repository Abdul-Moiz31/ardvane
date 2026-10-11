# Changelog

Each version's section becomes its GitHub release notes automatically. To release, raise `VERSION` in
`app/backend/config.py`, add a section here, and merge the pull request.

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
