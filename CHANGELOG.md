# Changelog

Each version's section becomes its GitHub release notes automatically. To release, raise `VERSION` in
`app/backend/config.py`, add a section here, and merge the pull request.

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
