# What I tried — and what actually worked

| What I tried | Result | Why |
|---|---|---|
| Deleting the malicious files in a new commit | ❌ Came back | The malware stayed in history and on other branches; the next infected push restored it. |
| Rewriting repository history | ⚠️ Worked until the next push | Correct, but the attacker still had working credentials and collaborators were still infected. |
| Reinstalling macOS | ⚠️ Clean for 3 days | The machine was clean, but infected repositories and collaborators re-infected it. |
| Revoking tokens | ⚠️ Partial | Revoking without also signing out sessions, removing SSH keys and OAuth apps on **every** account left doors open. |
| Generic antivirus | ❌ Missed it | The dropper is plain JavaScript in an innocent-looking folder; nothing flagged it. |
| Scanning my repositories | ❌ False sense of safety | The repos looked clean while the dropper sat elsewhere on the Mac. |
| Paid scanning tools | ❌ Mostly out of reach | The ones that understood this campaign were mostly paid. |
| Community scanners for this campaign | ✅ Helpful | Open-source detectors by researchers and other victims taught me what to look for — but each missed some variants (e.g. fake fonts in folders whose names contain spaces). |
| Reading the research | ✅ Essential | Understanding *how* it spreads (stolen credentials + collaborators + auto-run editor tasks) was what finally explained why it kept coming back. |
| AI-assisted investigation | ✅ Turned the tide | Systematic, read-only investigation of the whole machine, the GitHub account and every repository's history, in one go. |

## What finally worked

Doing **everything at once, in the right order**:

1. Revoke **all** access on **all** accounts first — sessions, passwords, tokens, OAuth apps, SSH keys.
2. Find and remove what's on the machine — including places no repo scan looks.
3. Rewrite the history of every branch, verify from fresh downloads, then force-push.
4. Re-clone local copies; delete forks you don't need; warn collaborators.
5. Rotate every secret that was on the machine and sign out every session.
6. Put up guards that work **automatically**, because the next attempt will come through a collaborator or a
   package you didn't choose:
   - block infected clones and pushes (this kit's git hooks and safe clone),
   - block force-pushes on GitHub (rulesets),
   - stop editors and npm from running code on their own,
   - keys that can't be copied off the machine,
   - a daily check that also notices if the protections are switched off.
