# If DANGER is found — step by step

Don't panic, and don't skip steps. The order matters: if you clean before cutting off access, the attacker puts
the malware straight back.

## 0. In the first 5 minutes

- [ ] **Don't open** the affected project in VS Code / Cursor / any editor. **Don't run** `npm install`, `npm run …`, or any script in it.
- [ ] If a daily check found an **implant or a connection to an attacker server**, disconnect the computer from the internet (Wi-Fi off) while you work through step 2 **from your phone or another computer**.
- [ ] Take a screenshot / copy of the scanner output. You'll want it for your team and for GitHub Support.

## 1. Find out how far it went

Run these (all read-only):

```bash
checkrepo <the affected folder>                 # what exactly is infected
bash ~/.checkrepo/daily-check.sh                # is anything running or installed on this machine?
python3 scanner/check-my-projects.py # any known-malicious packages in your projects?
```

Then on GitHub (web, ideally from another device):

- [ ] **Your repositories** page — sort by "Last updated". Many repos updated within minutes of each other, at a time you weren't working, is the worm's signature.
- [ ] **Settings → Security log** — look for `git.push`, `oauth_access.create`, `personal_access_token.create`, logins from IP addresses that aren't yours.
- [ ] Repos of **organizations / other people** you can push to — the worm pushes there too.

## 2. Cut off access (do this before cleaning anything)

From another device if possible:

- [ ] GitHub → **Settings → Sessions**: sign out every session.
- [ ] **Change your GitHub password**; turn on two-factor with a **passkey or authenticator app** (not SMS).
- [ ] **Settings → Developer settings → Personal access tokens**: delete all (classic and fine-grained).
- [ ] **Settings → Applications → Authorized OAuth Apps**: revoke all you don't recognise — and the GitHub CLI.
- [ ] **Settings → SSH and GPG keys**: delete all keys. You'll add new ones later.
- [ ] Repeat for **every** GitHub account you used on that machine (e.g. a separate work account).
- [ ] On the machine: `gh auth logout`, and remove saved GitHub logins from your keychain / credential manager.

## 3. Warn the people you code with

The worm spreads through collaborators. Send a short message to every person or organization whose repos you can push to:

> My GitHub account was compromised by the PolinRider malware. It may have force-pushed malware into your repos
> from my account around <time>. Please don't open those repos in VS Code/Cursor or run npm install, revert/clean
> my recent commits, and check your own machine with https://github.com/Abdul-Moiz31/polinrider-survival-kit

If a **collaborator's** commit brought the malware to you, ask them to check their machine before they push again.

## 4. Clean this machine

- [ ] Remove the malware files the scans found (move them to the Trash / Recycle Bin, then empty it).
- [ ] Check startup items: macOS `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`; Windows Task Scheduler, Startup folder, `HKCU\...\Run`.
- [ ] Check your shell files (`~/.zshrc`, `~/.bashrc`, PowerShell `$PROFILE`) for lines you didn't add.
- [ ] Run the daily check again until it says `ALL CLEAN`.
- [ ] **Strongly consider reinstalling the operating system.** This malware family includes remote-control backdoors; no scan can prove
      nothing else was left behind. Restore only your **files** afterwards — not apps, settings or a full Time Machine / system image restore.
- [ ] ⚠️ A reinstall alone did **not** protect the author: the infection came back days later through infected repositories and a
      collaborator's merge. Do steps 2, 3, 5 and 6 as well.

## 5. Clean your repositories

Follow [`clean-github-repos.md`](clean-github-repos.md). In short: rewrite history to remove the malware from **every**
branch (a normal "remove malware" commit leaves it in history), verify, force-push, then turn on branch protection.

Also re-clone your local copies from the cleaned GitHub versions — an old local copy still has the infected history,
and a `git checkout` or `git stash pop` can bring the malware back.

## 6. Rotate secrets

Assume **everything that was on the machine** was stolen: see [`secrets-rotation-checklist.md`](secrets-rotation-checklist.md).
The stealers in this campaign also take **browser cookies**, so sign out of all other sessions on every important site —
changing a password doesn't always end existing sessions.

## 7. Harden and keep watching

- [ ] Install this kit (scanner + hooks + safe clone) and the daily routine.
- [ ] Work through [`hardening-checklist.md`](hardening-checklist.md).
- [ ] Watch the daily report and your GitHub security log for at least a month.
