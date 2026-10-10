# The dashboard

A window for everything the kit does: scan, see results, turn protection on and off, choose when the daily check
runs, read the guides. It runs **only on your computer**, with no account and no tracking.

## Open it

```bash
python3 app/dashboard.py          # Windows: py -3 app\dashboard.py
```

Your browser opens the dashboard. To skip the terminal next time, go to **Protection → App icon → Add app icon**.
That puts an icon in your Applications folder (macOS), Start menu (Windows) or applications menu (Linux).

The dashboard stops by itself a few minutes after you close its tab. Clicking the icon again opens it again.

## What's in it

| Page | What you can do |
|---|---|
| **Overview** | One status: protected, worth a look, or action needed. Run a scan, see when the next daily check runs and change its time, view the last 30 days as a chart. |
| **To-do** | Concrete steps, each with a checkbox. Every finding becomes a short checklist, a DANGER opens the full recovery checklist (in the guide's order), one-time setup steps (2FA, Vigilant mode, rulesets…) and weekly / monthly routine checks. |
| **Scan** | Full or quick scan; your whole home folder or only your project folders; optionally your GitHub account. Live progress, then the results grouped by check, with *Show in Finder / Explorer* and *What to do* buttons. Mark harmless warnings as yours to hide them next time. |
| **Protection** | Turn on the git hooks, safe clone, npm and editor hardening. You see the exact changes before anything happens, and **Remove protection** undoes all of it. |
| **Reports** | Every daily check and scan, with a 90-day chart. |
| **Learn** | All the guides from `docs/`, readable offline. |
| **Settings** | Daily check time (09:00 by default), which folders are scanned, what the app may fix for you, and the optional GitHub check. |

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
| **Automatic** | Safe fixes run as soon as a scan or the daily check finds the problem. You get a summary and can undo each one. |
| **Off** | Only report; you fix everything yourself. |

| Fix | Ask me | Automatic |
|---|---|---|
| Editor auto-run on / Workspace Trust off | ✅ | ✅ |
| npm install scripts allowed | ✅ | ✅ |
| The kit's git hooks switched off | ✅ | ✅ |
| Malware in a known malware location (`scanner/lists/malware-paths.txt`) | ✅ | ✅ (names marked `ask` in the list always ask) |
| A malware process that is running | ✅ | asks first |
| An infected project folder, or a loose script that only *might* be malware | ✅ | asks first |
| Anything on GitHub, rotating secrets | — | — (stays in your to-do list) |

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

If the [GitHub CLI](https://cli.github.com) is installed and logged in (`gh auth login`), private repositories are
included. Your token stays inside `gh`, and the kit never reads or stores it. Without `gh`, only public repositories
are checked. Repositories that were already scanned clean are skipped until they get a new push.

You can also run it on its own: `python3 scanner/github_check.py <username>`.

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
