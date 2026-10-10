# ClickFix — "paste this command to fix it"

**ClickFix** pages show a fake error — your camera or microphone "isn't working" in a Zoom / Teams / Google Meet
look-alike, or a "verification" step — and tell you to copy a command into Terminal (macOS) or PowerShell / Run
(Windows). The command installs malware. North Korean operators use it in fake interviews and meetings, and in
2026 also through **malicious ads** in ordinary searches, so it now reaches everyday Mac users, not only developers.

## How it reaches you

- A meeting invite (often via Telegram or LinkedIn) leading to a look-alike video-call site.
- A fake job interview platform.
- Search ads for real products leading to fake download / "fix" pages.

## What it does

- The pasted command downloads and runs a script (on macOS sometimes AppleScript) that installs stealers and
  backdoors (e.g. FlexibleFerret) — taking browser data, crypto wallets and cloud keys.

## How to spot it

- Any website asking you to open Terminal / PowerShell and paste something. Real meeting tools never do this.

## How to protect yourself

- **Never paste commands from a website, meeting page or chat into a terminal.** Close the page.
- If you already did: disconnect, and follow [`../after-a-scan/if-danger-found.md`](../after-a-scan/if-danger-found.md).

## Sources

1. SecurityWeek — "North Korean Hackers Use AppleScript ClickFix in Fresh macOS Attacks": https://www.securityweek.com/north-korean-hackers-use-applescript-clickfix-in-fresh-macos-attacks/
2. Daily Security Review — "DPRK macOS Malvertising Uses ClickFix to Steal Wallets and Cloud Keys": https://dailysecurityreview.com/threat-actors/dprk-macos-malvertising-uses-clickfix-to-steal-wallets-and-cloud-keys/
3. Security Arsenal — "Lazarus Group ClickFix campaign: macOS defense and detection guide": https://securityarsenal.com/blog/lazarus-group-clickfix-campaign-macos-defense-and-detection-guide
4. GitLab Security — BeaverTail variant distributed via ClickFix lure: https://gitlab-com.gitlab.io/gl-security/security-tech-notes/threat-intelligence-tech-notes/north-korean-malware-sept-2025/
