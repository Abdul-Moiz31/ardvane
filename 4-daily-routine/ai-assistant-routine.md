# Optional: daily check run by an AI assistant

A ready-made prompt for AI coding assistants or agents that can run scheduled tasks on your computer
(schedule it daily, e.g. cron `0 9 * * *`). Replace `<your-github-username>` and adjust the folder list.
Not needed for the kit to work — the scripts in `mac/` and `windows/` do the daily check on their own.

It complements `daily-check.sh` / `daily-check.ps1` by also checking your **GitHub account** for the worm's
typical burst of pushes.

---

```text
You are running a daily, READ-ONLY security check for this computer and the GitHub account <your-github-username>.

Background: developers are being targeted by the PolinRider / Contagious Interview campaigns (North Korea / Lazarus).
They steal GitHub credentials and force-push malware into every repo the victim can reach: fake font files that are
JavaScript, api.js droppers, .vscode/tasks.json auto-running node on a fake font, config files with obfuscated code
hidden after a long run of spaces, and .gitignore entries hiding temp_auto_push.bat / config.bat.

Rules: read-only. Never delete, move, modify, push, revoke or install anything. Never run code from a repository,
never run npm/node on project files, never open projects in an editor. Don't print secrets. If a check can't run,
say so — never claim it passed.

On this computer:
1. Run the kit's daily check (macOS: bash ~/.checkrepo/daily-check.sh ; Windows: powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\.checkrepo\daily-check.ps1")
   with the environment variable CHECKREPO_NO_NOTIFY=1, and include its VERDICT and every 🛑 / TAMPERED / ⚠️ line.
2. Summarize established network connections by process and flag any node/python process talking to the internet.

On GitHub (use `gh` if logged in, otherwise the public REST API — and say private repos weren't checked):
1. List repos pushed in the last 24 hours. Flag SUSPICIOUS if more than 5 repos were pushed within one hour, or if
   pushes happened between midnight and 7am local time.
2. List PushEvents in the last 24 hours (users/<your-github-username>/events), including pushes to other people's repos.
3. For each recently pushed branch, download its files as plain text into a temporary folder (never into my
   project folders), run `checkrepo --json <temp folder>`, report findings, then delete only that temp folder.
4. Report the number of SSH keys and SSH signing keys on the account and flag any change.
5. Remind me to look at https://github.com/settings/security-log, /settings/tokens and /settings/applications
   (make it prominent on Mondays).

Report: one line verdict — "✅ ALL CLEAN" or "⚠️ ACTION NEEDED — <summary>" — then a short table
(Check | Result ✅ / ⚠️ / ❓ not checked). Only if something is DANGER or TAMPERED, add "What to do": don't open the
affected project, revoke GitHub sessions/tokens/SSH keys, change the GitHub password, and consider reinstalling the OS.
Plain language — the reader is not a security expert.
```
