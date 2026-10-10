"""What the to-do list asks people to do. Data only; the logic lives in tasks.py.

Each step is (text, link) where link is "" or an https:// URL or an in-app route ("#learn/...").
Task ids are stable: progress is saved under them in ~/.checkrepo/tasks.json.
"""
import re

GH = "https://github.com/settings/"
GUIDE = "#learn/after-a-scan/"

# ---------------------------------------------------------------------------------------------- after a DANGER
# Created together, once, when the first DANGER of an incident is found. Order follows if-danger-found.md.
INCIDENT = [
    {"id": "incident-1-stop", "title": "Stop: don't open or run the affected project",
     "detail": "Opening it in an editor or running npm install can start the malware.",
     "steps": [("Don't open the affected project in VS Code, Cursor or any editor", ""),
               ("Don't run npm install, npm run or any script inside it", ""),
               ("If the scan found malware running or an attacker connection: turn Wi-Fi off and do the next steps from your phone", ""),
               ("Keep the scan report — you'll need it for your team and for GitHub Support", "#reports")],
     "link": GUIDE + "if-danger-found.md"},
    {"id": "incident-2-cut-access", "title": "Cut off the attacker's access to GitHub",
     "detail": "Do this before cleaning anything, or the malware is pushed straight back. Use another device if you can.",
     "steps": [("Sign out every GitHub session", GH + "sessions"),
               ("Change your GitHub password and use a passkey or authenticator app for 2FA", GH + "security"),
               ("Delete all personal access tokens (classic and fine-grained)", GH + "tokens"),
               ("Revoke authorized OAuth apps you don't recognise, including the GitHub CLI", GH + "applications"),
               ("Delete all SSH keys (add new ones later)", GH + "keys"),
               ("Repeat for every GitHub account you used on this computer (for example a work account)", ""),
               ("On this computer: run `gh auth logout` and remove saved GitHub logins from your keychain", "")],
     "link": GUIDE + "if-danger-found.md"},
    {"id": "incident-3-scope", "title": "Find out how far it went",
     "detail": "The worm pushes into every repository you can reach, including other people's.",
     "steps": [("Open your repositories sorted by \"Last updated\" — many repos updated within minutes is the worm's signature", "https://github.com/?tab=repositories"),
               ("Read your security log for pushes, new tokens and logins you don't recognise", GH + "security-log"),
               ("Check the repositories of organizations and people you can push to", "")],
     "link": GUIDE + "if-danger-found.md"},
    {"id": "incident-4-warn", "title": "Warn the people you code with",
     "detail": "The worm spreads through collaborators. A short message stops it reaching them.",
     "steps": [("Message every person or organization whose repositories you can push to (there's a ready-made text in the guide)", GUIDE + "if-danger-found.md")],
     "link": GUIDE + "if-danger-found.md"},
    {"id": "incident-5-clean-machine", "title": "Clean this computer",
     "detail": "Remove what the scan found, then scan again until it's clean.",
     "steps": [("Move the malware files the scan found to the Trash / Recycle Bin and empty it", ""),
               ("Check your startup items for anything you didn't install", ""),
               ("Check ~/.zshrc, ~/.bashrc or your PowerShell profile for lines you didn't add", ""),
               ("Run a full scan again until it says no malware", "#scan"),
               ("Consider reinstalling the operating system — no scan can prove a backdoor left nothing behind", "")],
     "link": GUIDE + "if-danger-found.md"},
    {"id": "incident-6-clean-repos", "title": "Clean your GitHub repositories",
     "detail": "A normal \"remove malware\" commit leaves it in history. Rewrite every branch, then re-clone your local copies.",
     "steps": [("Follow the repository cleaning guide for every infected repository", GUIDE + "clean-github-repos.md"),
               ("Turn on rulesets that block force-pushes on your repositories", GUIDE + "hardening-checklist.md"),
               ("Delete old local copies and clone the cleaned versions again", "")],
     "link": GUIDE + "clean-github-repos.md"},
    {"id": "incident-7-secrets", "title": "Rotate your secrets",
     "detail": "Assume everything on this computer was stolen, including browser cookies.",
     "steps": [("Work through the secrets rotation checklist (cloud keys, .env files, npm/PyPI tokens, wallets)", GUIDE + "secrets-rotation-checklist.md"),
               ("Sign out of all other sessions on important sites — a new password doesn't always end them", "")],
     "link": GUIDE + "secrets-rotation-checklist.md"},
]

# ---------------------------------------------------------------------------------------------- one-off setup
# "auto" names a protection-status check that completes the task by itself.
SETUP = [
    {"id": "setup-protection", "title": "Turn on automatic protection", "auto": "protection",
     "detail": "Checks every clone, pull and push, blocks npm install scripts and stops editors from auto-running code.",
     "steps": [("Open Protection and press \"Turn on protection\"", "#protection")], "link": "#protection"},
    {"id": "setup-daily", "title": "Schedule the daily check", "auto": "routine",
     "detail": "A short read-only check every day that also notices if malware switches your protection off.",
     "steps": [("Choose a time on the Overview or in Settings", "#settings")], "link": "#settings"},
    {"id": "setup-2fa", "title": "Use a passkey or authenticator app for GitHub 2FA",
     "detail": "Stops a stolen password from being enough. Avoid SMS codes.",
     "steps": [("Open GitHub's password and authentication settings and add a passkey or authenticator app", GH + "security")],
     "link": GUIDE + "hardening-checklist.md"},
    {"id": "setup-vigilant", "title": "Turn on Vigilant mode and sign your commits",
     "detail": "Commits the worm makes without your signing key then show as \"Unverified\".",
     "steps": [("Tick \"Flag unsigned commits as unverified\"", GH + "keys"),
               ("Set up commit signing with an SSH key", "https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification")],
     "link": GUIDE + "hardening-checklist.md"},
    {"id": "setup-rulesets", "title": "Block force-pushes on your repositories",
     "detail": "The strongest single protection: even with a stolen token, the worm can't rewrite your history.",
     "steps": [("Add a ruleset to each important repository: block force pushes and deletion, require signed commits", GUIDE + "hardening-checklist.md")],
     "link": GUIDE + "hardening-checklist.md"},
    {"id": "setup-ssh-hardware", "title": "Keep SSH keys in hardware-backed storage",
     "detail": "Keys in the Secure Enclave or on a security key can't be copied off your computer by a stealer.",
     "steps": [("Use Secretive (macOS) or a FIDO2 security key, one key per GitHub account", GUIDE + "hardening-checklist.md")],
     "link": GUIDE + "hardening-checklist.md"},
]

# ---------------------------------------------------------------------------------------------- routine habits
RECURRING = [
    {"id": "weekly-security-log", "every_days": 7, "title": "Read your GitHub security log",
     "detail": "Look for pushes, new tokens and logins you don't recognise.",
     "steps": [("Open the security log and scan the last week", GH + "security-log")], "link": GUIDE + "hardening-checklist.md"},
    {"id": "weekly-access", "every_days": 7, "title": "Check who can act as you on GitHub",
     "detail": "Tokens, SSH keys and apps you didn't create are how the worm keeps access.",
     "steps": [("Personal access tokens: delete any you don't use", GH + "tokens"),
               ("SSH and GPG keys: every key should be one you recognise", GH + "keys"),
               ("Authorized apps: revoke anything you don't use", GH + "applications")],
     "link": GUIDE + "hardening-checklist.md"},
    {"id": "monthly-extensions", "every_days": 30, "title": "Review your editor extensions",
     "detail": "Malicious extensions (GlassWorm) hide in look-alike names. Keep only verified publishers.",
     "steps": [("Open the Extensions view in VS Code / Cursor and remove anything you don't use or recognise", "")],
     "link": "#learn/attacks/glassworm-malicious-extensions.md"},
    {"id": "monthly-update-kit", "every_days": 30, "title": "Update the kit",
     "detail": "New malicious packages and indicators are added as researchers publish them.",
     "steps": [("Run `git pull` in the kit's folder", ""),
               ("Open Protection and press \"Update protection\" if it's offered", "#protection")],
     "link": "#protection"},
]

# ---------------------------------------------------------------------------------------------- per finding
# First matching rule wins. "level" limits a rule to danger or warn findings ("" = both).
FINDING_RULES = [
    {"match": re.compile(r"INFECTED|DANGER in|malicious package", re.I), "level": "danger",
     "title": "Remove the infected project", "detail": "The scan found malware in this project.",
     "steps": [("Don't open it in an editor and don't run npm install in it", ""),
               ("If it's your repository: clean it on GitHub first, then clone it again", GUIDE + "clean-github-repos.md"),
               ("If it's someone else's (a download, a coding test): move the folder to the Trash and empty it", ""),
               ("Run a new scan to confirm it's gone", "#scan")]},
    {"match": re.compile(r"found:|malware (script|startup|reference)|process:|connection to|scheduled task:|Run key:|startup folder:", re.I), "level": "danger",
     "title": "Remove malware from this computer", "detail": "Malware files, a running process or an attacker connection were found.",
     "steps": [("Cut off GitHub access first (see \"Cut off the attacker's access\")", GUIDE + "if-danger-found.md"),
               ("Move the reported file or startup item to the Trash and empty it", ""),
               ("Run a new scan to confirm it's gone", "#scan")]},
    {"match": re.compile(r"pushed within one hour", re.I), "level": "",
     "title": "Check your recent GitHub pushes", "detail": "Many repositories were pushed at once — that's how the worm spreads.",
     "steps": [("Open your repositories sorted by \"Last updated\" and confirm you made these pushes", "https://github.com/?tab=repositories"),
               ("Check the security log around that time", GH + "security-log"),
               ("If it wasn't you, start the recovery checklist", GUIDE + "if-danger-found.md")]},
    {"match": re.compile(r"extension", re.I), "level": "warn",
     "title": "Check a new editor extension", "detail": "A new extension was installed or updated recently.",
     "steps": [("Open the Extensions view and find it", ""), ("Make sure its publisher is verified and has a real history", ""),
               ("Uninstall it if you didn't install it yourself", "")]},
    {"match": re.compile(r"automatic tasks|Workspace Trust", re.I), "level": "warn",
     "title": "Make your editor safe to open projects in", "detail": "Any folder you open can run code with these settings.",
     "steps": [("Turn on protection (it fixes these settings)", "#protection")]},
    {"match": re.compile(r"startup item|cron|scheduled task|Run key|LaunchAgent|Apple-named", re.I), "level": "warn",
     "title": "Check a program that starts automatically", "detail": "Make sure you know what this is.",
     "steps": [("Open the item and see which program it starts", ""), ("Keep it only if you installed that app yourself", ""),
               ("If you don't recognise it, follow the recovery guide", GUIDE + "if-danger-found.md")]},
    {"match": re.compile(r"\.zshrc|\.bashrc|\.bash_profile|\.profile|PROFILE|shell", re.I), "level": "warn",
     "title": "Check your shell startup file", "detail": "It was changed or runs downloaded code.",
     "steps": [("Open the file and read the reported line", ""), ("Remove anything you didn't add yourself", "")]},
    {"match": re.compile(r"hosts", re.I), "level": "warn",
     "title": "Check your hosts file", "detail": "Custom entries can redirect websites.",
     "steps": [("Make sure every custom entry is one you added", "")]},
    {"match": re.compile(r"GitHub check could not run|Couldn't check @", re.I), "level": "warn",
     "title": "Fix the GitHub check", "detail": "Your GitHub account wasn't checked.",
     "steps": [("Check your username in Settings", "#settings"), ("If you hit GitHub's hourly limit, log in with `gh auth login` or try later", "")]},
]
FINDING_RULES.insert(0, {
    "match": re.compile(r"TAMPERED", re.I), "level": "danger",
    "title": "Find out why your protection was changed", "detail": "Something modified the kit's files or switched the git hooks off.",
    "steps": [("If you didn't change it yourself, treat this as an infection and start the recovery checklist", GUIDE + "if-danger-found.md"),
              ("Turn protection on again", "#protection"), ("Run a full scan", "#scan")]})

DEFAULT_RULES = {
    "danger": {"title": "Act on this finding", "detail": "The scan found specific evidence of malware.",
               "steps": [("Follow the recovery guide, starting with cutting off access", GUIDE + "if-danger-found.md"),
                         ("Run a new scan to confirm it's gone", "#scan")]},
    "warn": {"title": "Review this item", "detail": "Unusual, but often harmless — for example something you installed yourself.",
             "steps": [("Read the item and decide whether you recognise it", "")]},
}


def rule_for(level, text):
    for rule in FINDING_RULES:
        if rule["level"] in ("", level) and rule["match"].search(text):
            return rule
    return DEFAULT_RULES[level]
