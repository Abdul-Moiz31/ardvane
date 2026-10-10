# After a scan — what to do

| Your situation | Read |
|---|---|
| A scan, hook or daily check said **DANGER / ACTION NEEDED / TAMPERED** | [`if-danger-found.md`](if-danger-found.md) — step by step, in order |
| Malware got pushed to your **GitHub repos** | [`clean-github-repos.md`](clean-github-repos.md) |
| You need to know **which secrets to change** | [`secrets-rotation-checklist.md`](secrets-rotation-checklist.md) |
| Everything is clean and you want to **stay** safe | [`hardening-checklist.md`](hardening-checklist.md) |

The single most important lesson from a real recovery: **cleaning the code is not enough.**
If the attacker still has a working token, or one of your collaborators' machines is still infected, the malware
comes back — sometimes the very next day. Always do the steps in this order:

1. **Stop it spreading** (don't open the project, don't run npm install, warn collaborators).
2. **Cut off access** (revoke every GitHub token, session, SSH key; sign out everywhere).
3. **Clean the machine** (remove the malware; reinstall the OS if you can).
4. **Clean the repositories** (rewrite history, verify, then protect branches).
5. **Rotate secrets** (everything that was on the machine).
6. **Harden and monitor** (this kit + the hardening checklist).
