# Changelog

Each version's section becomes its GitHub release notes automatically. To release, raise `VERSION` in
`app/backend/config.py`, add a section here, and merge the pull request.

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
