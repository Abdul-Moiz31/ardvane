# Timeline

## Before it started — a fake SDK

I was using a web-scraping service's SDK in one of my projects. When I later scanned the project, I found the
package wasn't the real one: someone had added a **fake npm package impersonating the vendor's SDK**. I only
confirmed it when I contacted the vendor, who told me it wasn't theirs. Fake packages that look like a real
company's SDK are one of the ways this campaign gets in.

## Attack 1 — early September: config files pushed into every repo

My repositories suddenly had changes I never made: build configuration files (`postcss.config.*`,
`tailwind.config.*`…) were modified and **automatically pushed into all my repos**. I believe it reached me through
teammates whose machines were already infected.

What I did:

- Removed the malicious changes from my repos and rewrote history.
- **Reinstalled macOS**, revoked my tokens and set everything up again from scratch.

I thought it was over.

## Attack 2 — mid-September: back on the freshly installed Mac

A few days after the reinstall it was back, with the same signature: a hidden `config.bat`, fake Font Awesome
font files that were really JavaScript, and modified config files — again committed to all my repositories.

What I later found on the Mac: a hidden folder created **three days after the reinstall** holding the
malware's network library, and two days later a dropper script hidden in a folder named
`~/Library/Application Support/VSCodeUpdater/` — a name chosen to look harmless.

What I remember about how it came back: a collaborator **merged an infected commit even though the CI check on it
was failing**. The very next day I was attacked again. Infected repositories and collaborators were re-infecting a
machine I had just wiped.

## Between attacks — weeks of cleaning

I rewrote history again, tried scanners (the good ones were mostly paid), read articles about these campaigns
and scanned my system again and again. My work repositories kept getting re-infected through different
contributors. Every scan of my laptop's repositories said "clean" — because the scans only looked at repositories,
not at the rest of the Mac where the dropper was hiding.

## Attack 3 — October 9, morning: ~150 repositories in 25 minutes

I woke up to emails: **deployments had failed** on my hosting platforms, even though I hadn't pushed anything.
On GitHub, almost every repository had been force-pushed within about **25 minutes**: my own repos, my forks, and
repositories in organizations I collaborate with. The worm had used my stolen GitHub access to push to everything it
could reach, rewriting my latest commits while keeping their old dates so the change was hard to spot.

The payload this time:

- obfuscated JavaScript appended to config files after ~150 spaces (off-screen in most editors and diff views),
- an `api.js` dropper in every package folder,
- fake fonts (`fa-solid-900.eot`, `fa-solid-500.woff2`) with a decoy Font Awesome bundle around them,
- `.vscode/tasks.json` that silently runs the fake font with `node` the moment the folder is opened in VS Code/Cursor,
- `.vscode/settings.json` that switches off VS Code's "allow automatic tasks?" warning,
- `.gitignore` changes that stopped ignoring `.env` files.

## The recovery — October 9 and 10

This time I went end to end, in the right order:

1. **Cut off access** on both my GitHub accounts: all sessions, tokens, OAuth apps and SSH keys revoked, passwords changed, two-factor with passkeys.
2. **Found the source on my Mac**: the dropper and its hidden library had been there since mid-September — earlier checks had missed them.
3. **Cleaned GitHub**: rewrote the history of 73 repositories (every branch), deleted 55 infected forks, verified
   5,160 commits from fresh downloads, and asked GitHub Support to purge the old pull-request copies.
4. **Re-cloned** every local repository from the cleaned versions — two old local copies still had infected history.
5. **Rotated secrets** and signed out every session (the stealers in this family take browser cookies too).
6. **Built protection**: the scanner, git hooks and safe clone in this kit, branch rulesets that block force-pushes,
   SSH keys that can't be copied off the machine, and a daily check every morning.

Since then, every daily check has been clean.
