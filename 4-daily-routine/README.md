# Daily routine — a security check every morning

The scanner and git hooks protect you when code **arrives**. The daily routine catches anything that slips
past them — and tells you if malware has switched your protections off.

Every morning it checks (read-only):

1. **Known malware locations** — stealer folders (`~/.n2`, `~/.n3`, `~/.npl`, `~/.pyp`, `~/.node_modules`), the
   `MicrosoftSystem64` implant and its LaunchAgents / scheduled tasks, the `VSCodeUpdater` dropper folder.
2. **Suspicious processes** — `MicrosoftSystem64`, `SvcHostUpdate`, node running a "font" file, `node -e` loaders.
3. **Startup items and shell files** changed in the last 24 hours, fake Apple-named LaunchAgents, suspicious cron / Run keys.
4. **Connections to known attacker servers.**
5. **All your git projects** with `checkrepo`, plus your Downloads folder.
6. **Your protections** — git hooks still on, the kit's files unmodified (SHA-256 fingerprints), npm `ignore-scripts`,
   editor automatic tasks off, editor extensions installed in the last 24 hours, macOS SIP / Gatekeeper.

It ends with one line — `ALL CLEAN`, `Clean, N item(s) worth a look` or `ACTION NEEDED` — shows a notification,
and saves the full report to `~/.checkrepo/reports/YYYY-MM-DD.txt`.

## Set it up

First install the scanner (`../3-checkrepo`). Then:

| | Schedule it | Run it now |
|---|---|---|
Run these from the repository folder:

| | Schedule it | Run it now |
|---|---|---|
| **macOS** | `bash 4-daily-routine/mac/install-routine.sh` (or `… install-routine.sh 8:30` for 08:30) | `bash ~/.checkrepo/daily-check.sh` |
| **Windows** 🧪 beta | `powershell -ExecutionPolicy Bypass -File 4-daily-routine\windows\install-routine.ps1 -At 08:30` | `powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\.checkrepo\daily-check.ps1"` |

- macOS uses **launchd**: if the Mac is asleep at the scheduled time, the check runs when it wakes (not if it was switched off).
- Windows uses **Task Scheduler** with "run as soon as possible after a missed start".
- **macOS privacy:** the first scheduled run may not be allowed to read Documents / Desktop / Downloads. The report
  says so ("can't read …" or "scanned 0 repositories"). Fix: System Settings → Privacy & Security → **Full Disk Access**
  → add `/bin/bash` (press ⌘⇧G in the file picker and type `/bin/bash`).
- Choose which folders are scanned: list them in `~/.checkrepo/projects.txt`, one per line, `#` for comments
  (default: Documents, Desktop, Downloads, `~/code`, `~/projects`, `source\repos`).
- After updating the kit, re-run the install-routine script so the fingerprints are refreshed.
- Remove just the routine: `bash 4-daily-routine/mac/install-routine.sh --remove` / `install-routine.ps1 -Remove`.
  (The kit's uninstaller also removes it.)

## Reading the report

| You see | Do this |
|---|---|
| `ALL CLEAN` | Nothing. |
| `worth a look` | Read the item. Usually it's something you did (installed an extension, edited `.zshrc`). If you didn't, treat it as DANGER. |
| `ACTION NEEDED` / `🛑` / `TAMPERED` | Stop. Don't open the affected project. Follow [`../6-after-a-scan/if-danger-found.md`](../6-after-a-scan/if-danger-found.md). |

Also do this by hand once a week (no tool can read it for you): open your **GitHub security log**, **tokens** and
**authorized apps** pages — see [`../6-after-a-scan/hardening-checklist.md`](../6-after-a-scan/hardening-checklist.md).

## Optional: let an AI assistant run it

If you use an AI coding assistant that can run scheduled tasks,
[`ai-assistant-routine.md`](ai-assistant-routine.md) is a ready-made prompt that runs the same checks and also looks at your
GitHub account for burst-pushes.
