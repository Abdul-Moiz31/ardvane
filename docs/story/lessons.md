# Lessons I'd tell every developer

1. **It's not just your laptop.** This malware lives in your machine, your repositories, your collaborators' machines
   and in credentials it already stole. Clean one and the others bring it back.

2. **Cut off access before you clean.** Otherwise the attacker re-pushes while you're still cleaning.

3. **A reinstall is not a cure on its own.** Mine lasted three days, because I opened repositories and merged work that
   were still infected.

4. **Never merge a failing PR "to fix later".** An infected commit often breaks the build. A red CI check on a
   collaborator's PR is a reason to stop and look.

5. **Opening a folder can run code.** VS Code / Cursor tasks with `"runOn": "folderOpen"` execute the moment you open a
   project. Turn automatic tasks off and keep Workspace Trust on.

6. **Fake packages look real.** Install SDKs only by the exact name in the vendor's documentation. If something looks
   off, ask the vendor — that's how I confirmed mine was fake.

7. **"Remove malware" commits leave the malware in history.** Rewrite history on every branch, then protect your
   branches so force-pushes are blocked even with a stolen token.

8. **Your scans can lie to you.** "All repos clean" meant nothing while a dropper sat in an innocent-looking folder.
   Check the machine, the account and the repositories.

9. **Changing passwords isn't signing out.** Stolen browser cookies keep working. Sign out of all other sessions everywhere.

10. **Make protection automatic.** You won't remember to scan every repo you clone. Hooks, rulesets and a daily check will.
