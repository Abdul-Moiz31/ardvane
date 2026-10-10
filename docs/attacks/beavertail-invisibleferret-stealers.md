# BeaverTail, InvisibleFerret and friends — the stealers

**BeaverTail** is a JavaScript stealer and downloader used in the Contagious Interview campaigns; it typically
installs **InvisibleFerret**, a Python backdoor. Related families include **OtterCookie** and the macOS
**FlexibleFerret**. Together they steal what's on a developer's machine and give the attacker remote control.

## How it reaches you

- A fake job test, a malicious npm package, a compromised repository, or a ClickFix command.

## What it does

- Searches browser profile folders (Chrome, Brave, Opera and others) for **saved passwords and session cookies**.
- Targets **crypto wallets** and wallet extensions, and the **macOS Keychain**.
- Steals files and clipboard contents; installs a **Socket.IO-based remote-access trojan**.
- Reported 2026 change: InvisibleFerret delivered as **compiled binaries** (`.so` on macOS, `.pyd` on Windows) instead of
  plain Python, which evades rules written for scripts.

## How to spot it

- Hidden folders in your home folder such as `~/.n2`, `~/.n3`, `~/.npl`, `~/.pyp`, `~/.sysinfo`.
- A hidden `~/.node_modules` folder (a private package folder used by the loader — in one real case it contained only
  `socket.io-client`).
- Unexpected `node` / `python` processes talking to the internet; new LaunchAgents / scheduled tasks.
- The kit's [daily routine](../daily-routine.md) checks all of these every morning.

## How to protect yourself

- If you were infected: assume **all browser sessions, saved passwords, keys and wallets are compromised** — sign out
  everywhere and rotate ([checklist](../after-a-scan/secrets-rotation-checklist.md)); move crypto to a new wallet.
- Prefer a password manager over browser-saved passwords; keep SSH keys in hardware-backed storage.
- Reinstalling the OS is the only way to be certain after a backdoor ran — but also clean your repos and access, or it returns.

## Sources

1. Palo Alto Networks Unit 42 — Contagious Interview, BeaverTail and InvisibleFerret: https://unit42.paloaltonetworks.com/north-korean-threat-actors-lure-tech-job-seekers-as-fake-recruiters/
2. MITRE ATT&CK — BeaverTail (S1246): https://attack.mitre.org/software/S1246/
3. GitLab Security — "BeaverTail variant distributed via malicious repositories and ClickFix lure": https://gitlab-com.gitlab.io/gl-security/security-tech-notes/threat-intelligence-tech-notes/north-korean-malware-sept-2025/
4. Silent Push — Contagious Interview front companies (BeaverTail, InvisibleFerret, OtterCookie): https://www.silentpush.com/blog/contagious-interview-front-companies/
5. Infosecurity Magazine — "North Korean Actors Expand Contagious Interview Campaign with New Malware": https://www.infosecurity-magazine.com/news/north-korean-contagious-interview/
6. The420.in — Void Dokkaebi and compiled InvisibleFerret: https://the420.in/void-dokkaebi-fake-job-interviews-developer-malware-campaign/
