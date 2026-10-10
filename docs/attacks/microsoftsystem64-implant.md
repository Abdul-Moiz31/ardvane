# MicrosoftSystem64 — the cross-platform backdoor

A remote-access implant distributed through the malicious npm package **`js-logger-pack`** and linked by researchers
to North Korea. It is a **Node.js single-executable application** — a native binary with the JavaScript payload built
in — so it runs even without Node installed and names its process to look like a system service. JFrog reported that
the operator used **Hugging Face** both to host the malware and to receive stolen data.

## How it reaches you

- Installing `js-logger-pack` (or a package depending on it): a `postinstall` script starts a hidden background
  downloader while the install appears to finish normally.
- The downloader fetches a platform-specific binary from a Hugging Face repository (`Lordplay/system-releases`, per JFrog).

## What it does

- Persists on Windows, macOS and Linux; beacons to a hard-coded controller.
- Logs keystrokes, monitors the clipboard, and uploads stolen data to attacker-controlled Hugging Face datasets.

## How to spot it

Locations and names reported by researchers and community indicator lists:

- macOS: `~/Library/Application Support/MicrosoftSystem64`, LaunchAgent `~/Library/LaunchAgents/com.launchkeeper.MicrosoftSystem64.plist`
- Linux: `~/.local/share/MicrosoftSystem64`, `~/.config/systemd/user/MicrosoftSystem64.service`
- Windows: `%LOCALAPPDATA%\MicrosoftSystem64(.exe)`
- Working folders `~/.pcl-data`, `~/.pcl-state`; a process named `MicrosoftSystem64`.
- Related Windows chain reported by the community: `SvcHostUpdate.py` / `SvcHostUpdate.js` and `MicrosoftCLROptimization.vbs`.

The kit's daily check looks for all of these; `checkrepo` flags the file names and known SHA-256 fingerprints.

## How to protect yourself

- `npm config set ignore-scripts true` (the kit sets it) — the infection starts from an install script.
- Check your projects and global packages: `python3 scanner/check-my-projects.py`.
- If found: disconnect, follow [`if-danger-found.md`](../after-a-scan/if-danger-found.md), rotate everything, and reinstall the OS.

## Sources

1. JFrog Security Research — "js-logger-pack Operator Turns Hugging Face into a Malware CDN and Exfiltration Backend": https://research.jfrog.com/post/hugging-face-exfil/
2. Corgea — "js-logger-pack / MicrosoftSystem64 Hugging Face exfiltration": https://corgea.com/research/js-logger-pack-microsoftsystem64-huggingface-exfiltration
3. Cyber Security News — "Malicious npm package turns Hugging Face into malware CDN": https://cybersecuritynews.com/malicious-npm-package-turns-hugging-face/amp/
4. polinrider-cleaner — implant paths, names and hashes (`ioc/implant-paths.txt`, `ioc/hashes.txt`, MIT): https://github.com/meSingh/polinrider-cleaner
