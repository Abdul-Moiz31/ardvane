# Ardvane — the dashboard

A window for everything the kit does: scan, see results, turn protection on and off, choose when the daily check
runs, read the guides. It runs **only on your computer**, with no account and no tracking.

## Open it

```bash
ardvane                           # after `brew install abdul-moiz31/ardvane/ardvane` or `pipx install ardvane`
python3 app/dashboard.py          # from a clone of the repository (Windows: py -3 app\dashboard.py)
```

Your browser opens the dashboard. To skip the terminal next time, go to **Protection → Add app icon**. That adds an
Ardvane app to your Applications folder (macOS), Start menu (Windows) or applications menu (Linux), so you can open it
from Launchpad, Spotlight or the Dock like any other app.

Choose light, dark, or Auto (it follows your computer) at the bottom of the menu.

The dashboard closes itself about 20 minutes after you stop using it. Clicking the icon (or typing `ardvane`) opens it again.

## What's in it

| Page | What you can do |
|---|---|
| **Overview** | The security dashboard: one status, four numbers (threats, items to review, protection, next daily check), a single "Needs your attention" list combining fixes and to-dos, and the last 30 days as a chart. |
| **To-do** | Concrete steps, each with a checkbox. Every finding becomes a short checklist, a DANGER opens the full recovery checklist (in the guide's order), one-time setup steps (2FA, Vigilant mode, rulesets…) and weekly / monthly routine checks. |
| **Scan** | Full or quick scan; your whole home folder or only your project folders; optionally your GitHub account and the repositories you listed. Live progress, then the results grouped by check, with *Show in Finder / Explorer* and *What to do* buttons. Mark harmless warnings as yours to hide them next time. |
| **GitHub** | Block force pushes: one click adds a ruleset to each repository the last GitHub check found open (undo any time). Tell the owner: for a repository shared with you that carries malware, scan it and get the report its owner needs, to copy, save or open as an issue. Needs the GitHub CLI signed in. |
| **Secrets** | Credentials in plain text files (AWS, GitHub CLI, npm, Docker, git, PyPI, Kubernetes, Google Cloud) with how long ago each file changed and the steps to move off it. Ardvane never shows a secret and never edits these files. |
| **Protection** | Open a coding test safely (scan it, then open it in a throwaway Docker or Podman container that shares none of your files). Turn on the git hooks, safe clone, safe install, npm and editor hardening. You see the exact changes before anything happens, and **Remove protection** undoes all of it. |
| **Reports** | Every daily check and scan, with a 90-day chart. |
| **Learn** | All the guides from `docs/`, readable offline. |
| **Settings** | Daily check time (09:00 by default), which folders are scanned (added with Finder / the Windows folder picker), what the app may fix for you, the optional GitHub check and repositories to scan, and the signed detection list (see below). |

## Updates

When a new version of Ardvane is out, the Overview shows it with a line about what's new. **See what's new** shows the
release notes; **Update** then:

1. installs the new version the way you installed Ardvane: `brew upgrade` for Homebrew, `pipx upgrade` for pipx, or
   `git pull` for a clone (only when it has no local changes and is on `main`);
2. refreshes your protection (scanner, git hooks, shell setup) and re-registers the daily check, so its tamper
   fingerprints match the new files;
3. restarts the dashboard on the new version - the page reloads by itself.

Settings → Updates shows your version, when Ardvane last looked, a **Check now** button and an on/off switch. Ardvane
looks about twice a day while the dashboard is open, with one download from GitHub (PyPI for pipx installs) that sends
nothing about your computer. A pip install shows the command to run instead.

## The to-do list

Scans tell you what's wrong; the to-do list makes sure something is done about it.

- **Every finding becomes a task** with concrete steps and links (for example straight to GitHub's token page).
  Tick each step as you go, then mark the task as done.
- **A DANGER opens the recovery checklist**: stop, cut off access, find out how far it went, warn collaborators,
  clean the computer, clean the repositories, rotate secrets, in that order.
- **Fixes are verified.** If you mark something as done but a later scan or daily check still finds it, the task comes
  back and tells you so.
- **Warnings you recognise** can be marked "It's mine". They're hidden from future results.
- **Setup steps** (protection, daily check, 2FA, Vigilant mode, rulesets, hardware-backed SSH keys) tick themselves off
  where the dashboard can see they're done.
- **Routine checks** come back on schedule: your GitHub security log and access every week, and your editor extensions
  and kit updates every month.

The menu shows how many steps are open, and the Overview shows the next three. Progress is saved in
`~/.checkrepo/tasks.json`. The steps themselves live in `app/backend/tasks_catalog.py`, so adding one is a data change.

## Fixes — let the app do it

Some problems the kit can fix for you. Choose how in **Settings → Fixes**:

| Mode | What happens |
|---|---|
| **Ask me** (default) | Each fixable problem gets a **Fix…** button that shows exactly what will change before anything happens. |
| **Automatic: safe fixes** | Your editor, npm and git settings, and malware in known malware locations, as soon as a scan or the daily check finds them. |
| **Automatic: remove malware too** | Everything Ardvane finds is removed as soon as it is found: malware processes are stopped, malware files and extensions quarantined, injected code cut out of your projects. You get a summary and can undo each one. |
| **Off** | Only report; you fix everything yourself. |

| Fix | Ask me | Automatic: safe | Automatic: remove malware |
|---|---|---|---|
| Editor auto-run on / Workspace Trust off | ✅ | ✅ | ✅ |
| npm install scripts allowed | ✅ | ✅ | ✅ |
| The kit's git hooks switched off | ✅ | ✅ | ✅ |
| Malware in a known malware location (`scanner/lists/malware-paths.txt`) | ✅ | ✅ (names marked `ask` ask first) | ✅ |
| A malware process that is running | ✅ | asks first | ✅ |
| A loose script with malware code, a malicious editor extension | ✅ | asks first | ✅ |
| A shutdown / wipe line malware added to your shell start-up file | ✅ | asks first | ✅ (only that line) |
| **Inside an infected project:** code hidden after spaces in a config file, a fake font or other payload file, the worm's `.gitignore` lines and install scripts, hidden instructions in AI-agent files, malicious tasks, hooks and workflows | ✅ | asks first | ✅ (only the malicious part; your code stays) |
| Moving a whole infected project to quarantine | ✅ | asks first | asks first |
| Anything on GitHub, rotating secrets, updating a hijacked package | — | — | — (stays in your to-do list) |

How it stays safe:

- **Nothing is deleted.** Malware is moved to `~/.checkrepo/quarantine` with a record of where it came from, and made
  non-executable. It is kept as evidence and can be restored.
- **Everything can be undone** from **Protection → Fix history**, except stopping a process.
- **Fixes only act on what the fixer detects itself**: a fixed list of known malware paths, exact malware file names,
  the settings the kit manages, and project folders that `checkrepo` still flags at the moment of the fix. Paths are
  never taken from text inside a scanned file. A symlink is moved as a link, never followed. Protected places
  (`~/.ssh`, keychains, your home folder itself and the like) are refused.
- **Every fix is checked afterwards.** It only counts as done if the problem is gone.
- **The recovery checklist still opens.** Removing malware doesn't undo what it already stole, so the to-do list keeps
  you on the GitHub and secrets steps.

The daily check uses the same fixer (`scanner/autofix.py`) in Automatic mode. You can also run it yourself:
`python3 scanner/autofix.py list`, then `fix <id>`, `history` or `undo <id>`.

## The GitHub check (optional)

The worm uses stolen access to push itself into every repository you can reach. With **Settings → GitHub account**
turned on, scans and the daily check also:

- warn when more than 5 of your repositories were pushed within one hour, and
- download the main branch of each recently pushed repository into a temporary folder, scan it with `checkrepo`, and
  delete it again. Nothing from GitHub is ever run.

Every repository you can reach is listed, not only the first 100. There is no fixed size limit: a download holds only
the latest files of one branch (much less than the repository size GitHub shows), is streamed to disk, and stops only
if less than 2 GB of disk space would be left. Files over 20 MB (videos, models, datasets) are listed as not scanned.

**Which repositories.** By default every repository you can push to is covered: yours, your organizations' and
repositories other people shared with you - the worm spreads through all of them. Choose **Mine and my
organizations'** to leave out repositories other people shared with you (`--owned-only` for `github_check.py`).
While a scan runs, the Scan page shows the GitHub check live: each repository as it is audited and each branch as it
is scanned, with how much of a big repository has been downloaded.

**Repositories to scan.** In **Settings → GitHub** you can also list repositories one by one - yours, your
organization's or a teammate's, any repository your GitHub login can read - as `owner/name`, a github.com link or a
`git@github.com:` address. Every branch of each one is scanned with each scan and daily check, however long ago it was
pushed, and you can remove them again like folders. **Choose from my GitHub repositories** lists every repository
you can see - grouped as yours, organizations' and shared with you - to search and tick instead of typing names. This works without a username too. A listed repository that can't
be checked (a typo, or no access) is shown as a warning, never as clean.

If the [GitHub CLI](https://cli.github.com) is installed and logged in (`gh auth login`), private repositories are
included. Your token stays inside `gh`, and the kit never reads or stores it. Without `gh`, only public repositories
are checked. Repositories that were already scanned clean are skipped until they get a new push.

From the terminal: `ardvane check-github owner/name [more ...]` scans every branch of those repositories once, and
`python3 scanner/github_check.py <username>` checks an account. Add `--all-branches` to scan every branch of an
account's repositories (the worm pushes into all of them), `--days N` to look further back, `--max-repos N` to scan
more repositories in one run, and `--rescan` to scan again what was already clean.

## Safe install

With protection on, `npm`, `npx`, `pnpm`, `yarn`, `bun` and `pip` check packages before they install:

- **What is checked:** the packages you name and everything in the project's lockfile. When npm adds packages, the
  full dependency tree is worked out first in a private copy of the project (package metadata only: nothing runs and
  none of your files change). pip checks the packages you name and your requirement files.
- **Against:** Ardvane's own list (built in, plus the signed detection list) and, unless you turn it off under
  **Settings → Detections**, [OSV.dev](https://osv.dev)'s database of malicious packages. Only public package names and
  versions are sent; packages from a private registry never are. Answers are cached for a day.
- **If a package is known malware, nothing is installed.** If only some versions of a package were malicious and the
  version isn't known yet, you get a warning instead.
- **It never breaks your package manager:** commands that don't install (`npm run dev`) pass straight through, and if
  the check itself fails, the command runs as normal. Bypass once, only if you are sure: `command npm install ...`
  (PowerShell: `npm.cmd install ...`).

## Detections that keep up

Attackers change their code to slip past scanners, and many people rarely update their tools. Besides the detections
built into each version, Ardvane downloads a **signed list of new ones** (attacker servers and IPs, malware
fingerprints, malicious npm and PyPI packages) before each scan and daily check. **Settings → Detections** shows which
list you have, has an **Update now** button, and can turn automatic updates off. From the terminal:
`ardvane update-detections`.

The list is used only if it carries Ardvane's Ed25519 signature (checked by the app itself, against a key built into
it) and is newer than the copy you already have. It can only add detections - never remove one, and never name files
for Ardvane to move or change - so the worst a bad list could do is raise false alarms, and the signature stops even
that. If an update fails, the last good copy is used. How entries get into the list: [feed/README.md](../feed/README.md).

## Security design

The dashboard can change protection settings, so it is locked down like a small web service:

- It listens on **127.0.0.1 only**, on a random port. Nothing on your network can reach it.
- Every request needs a **random key** created when the dashboard starts. The key reaches your browser in the URL
  fragment (`#…`). Browsers never send that part to any server, and the page removes it from the address bar right away.
- Requests from **other websites are refused**. The `Host` header must be `127.0.0.1:<port>` (this stops DNS
  rebinding), cross-site `Origin`s are rejected, and changes must be sent as JSON (a hidden form can't do that).
- A strict **Content-Security-Policy** means only the dashboard's own scripts and styles can run, and the page can't
  be embedded in another site.
- It only accepts **paths it listed itself**. It shows only reports and guides it listed, and opens only files a scan
  reported.
- It **changes nothing itself**. Turning protection on or off and scheduling the daily check run the same reviewed
  scripts as the terminal commands (`mac/` or `windows/`), and the installer's dry run is shown first.
- **No dependencies**: Python's standard library on the backend, plain JavaScript modules in the browser. There is
  no npm, no build step and no CDN, so what you read in `app/` is exactly what runs.

## For developers

```
app/
├── dashboard.py        entry point
├── backend/            Python standard library only
│   ├── server.py       HTTP server, security checks, API routes
│   ├── scanjob.py      runs scan-my-machine and the GitHub check in the background, parses their events
│   ├── status.py       read-only protection status
│   ├── actions.py      runs the kit's install / routine scripts
│   ├── tasks.py        the to-do list rules · tasks_catalog.py  the steps (data only)
│   ├── fixes.py        dashboard side of scanner/autofix.py (one implementation for app and daily check)
│   ├── reports.py · docs.py · settings.py · launcher.py · system.py · config.py · cli.py
├── ui/                 plain JavaScript modules, no build step
│   ├── index.html · app.css
│   └── js/  main.js (router) · store.js · actions.js · components.js · charts.js · markdown.js · …
│            pages/ one file per page (overview, todo, scan, protection, reports, learn, settings)
└── tests/test_backend.py
```

- Tests: `python3 app/tests/test_backend.py` (uses a temporary home folder, so nothing on your computer is touched).
- The JavaScript is type-checked in CI with `// @ts-check` and JSDoc (`app/ui/jsconfig.json`). Nothing is compiled.
- The scan scripts report progress to the dashboard through `$SCAN_EVENTS`. See the header of `scan-my-machine.sh`.
- The product name is defined in one place: `APP_NAME` in `backend/config.py` (and the `<title>` in `ui/index.html`).
