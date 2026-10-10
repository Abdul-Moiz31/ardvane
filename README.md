<div align="center">

# 🛡️ polinrider-survival-kit

**Free, open-source protection for developers against North Korea's PolinRider / Contagious Interview malware.**

Scan your machine in one command · block infected clones and pushes automatically · recover step by step

[![Tests](https://github.com/Abdul-Moiz31/polinrider-survival-kit/actions/workflows/tests.yml/badge.svg)](https://github.com/Abdul-Moiz31/polinrider-survival-kit/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows%20(beta)-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

[Am I infected?](#-step-1--am-i-infected) ·
[Stay protected](#-step-2--stay-protected) ·
[How it works](#-how-it-works) ·
[Accuracy](#-accuracy) ·
[If you're infected](docs/after-a-scan/if-danger-found.md) ·
[Contributing](CONTRIBUTING.md)

</div>

---

## Why this exists

Developers are being targeted by state-sponsored malware that spreads **through code**: fake job interviews and coding
tests, fake npm packages, malicious editor extensions — and, once inside, a worm that uses your stolen GitHub access to
**force-push itself into every repository you can reach**, including your teammates' and your company's.

I was hit **three times in five weeks**. A clean reinstall of my Mac lasted three days. Deleting the malicious files,
rewriting history and revoking tokens didn't stop it, because it kept coming back through infected repositories and
collaborators. This kit is everything that finally worked, packaged so you don't lose the weeks I did.
→ [Read the full story](docs/story)

> 🛑 **Think you're infected right now?** Go to [`docs/after-a-scan/if-danger-found.md`](docs/after-a-scan/if-danger-found.md) — the order of the steps matters.

## ✨ Features

| | |
|---|---|
| 🔍 **One-command machine scan** | Read-only check of your whole computer: implants, running malware, startup items, attacker connections, editor settings, every git project and known malicious packages |
| 🧱 **Safe clone** | `git clone` downloads without writing project files, scans, and **blocks** infected repositories |
| 🚫 **Push guard** | `git push` is blocked if your repository contains malware, so you can't spread it to others |
| ⚙️ **Hardening** | VS Code / Cursor can't auto-run code when you open a folder; npm packages can't run install scripts |
| ☀️ **Daily check** | A scheduled morning check that also notices if malware has switched your protections off |
| 📦 **Infected package lists** | Known-malicious npm / PyPI / Packagist packages, with a checker for all your projects |
| 📚 **Attack library** | Every technique explained in plain language, with links to the original research |
| 🧭 **Recovery guides** | What to do if you're infected, how to clean GitHub history, which secrets to rotate |

No dependencies beyond Python 3.8+ and git. Nothing is sent anywhere. The repository contains **no real malware** —
tests build synthetic samples at runtime.

## 🔎 Step 1 — Am I infected?

One command, **read-only** — nothing is installed, changed or run from your projects. Takes about a minute.

**macOS / Linux**

```bash
git clone https://github.com/Abdul-Moiz31/polinrider-survival-kit.git
cd polinrider-survival-kit
bash scan-my-machine.sh
```

**Windows** 🧪 *beta*

```powershell
git clone https://github.com/Abdul-Moiz31/polinrider-survival-kit.git
cd polinrider-survival-kit
powershell -ExecutionPolicy Bypass -File .\scan-my-machine.ps1
```

No git? Click **Code → Download ZIP**, unzip, and run the same command inside the folder.
Projects stored elsewhere? `bash scan-my-machine.sh /path/to/projects` · machine checks only: `--quick`.

The scan ends with ✅ **CLEAN**, ⚠️ **worth a look** or 🛑 **INFECTED** — plus exactly what to do next — and saves a report.

<details>
<summary>What it checks</summary>

1. Known malware locations (stealer folders, the `MicrosoftSystem64` implant, disguised dropper scripts)
2. Malware running right now
3. Every program that starts automatically (LaunchAgents/Daemons, scheduled tasks, Run keys, cron)
4. Shell / PowerShell startup files and the hosts file
5. Connections to the campaign's known servers
6. Editor settings (auto-run tasks, Workspace Trust) and recently added extensions
7. Every git repository on your machine, plus Downloads and Desktop
8. Known malicious packages — declared, installed, nested, or installed globally
9. Built-in OS protections

</details>

## 🛡️ Step 2 — Stay protected

**macOS / Linux**

```bash
bash mac/install.sh --dry-run     # preview every change
bash mac/install.sh               # scanner + git hooks + safe clone + npm/editor hardening
bash mac/install-routine.sh       # optional: daily check at 09:00
```

**Windows** 🧪 *beta*

```powershell
powershell -ExecutionPolicy Bypass -File .\windows\install.ps1 -DryRun
powershell -ExecutionPolicy Bypass -File .\windows\install.ps1
powershell -ExecutionPolicy Bypass -File .\windows\install-routine.ps1
```

Open a new terminal and run `checkrepo --version`. Undo everything any time with `mac/uninstall.sh`
(or `uninstall.ps1`). The installer backs up every file it edits, never replaces an existing git hooks setup without
asking, and is safe to run again.

## ⚙️ How it works

| You do | The kit does |
|---|---|
| `git clone …` in a terminal | Fetches without writing project files → scans → **blocks** the clone if infected |
| `git pull`, `git checkout` | Scans and warns you before you open anything |
| `git push` | **Blocks** the push if the repository contains malware |
| Open a folder in VS Code / Cursor | Nothing runs on its own (automatic tasks off, Workspace Trust on) |
| `npm install` | Packages can't run install scripts |
| Every morning | Checks your machine, projects and protections — and notifies you |
| `checkrepo <folder>` | Scan anything before you open it (a download, a coding test, a colleague's repo) |

When everything is clean you won't notice it: a scan takes about **0.1–0.7 seconds per repository**.

The scanner (`checkrepo`) is a single dependency-free Python file that **only reads files** — it runs git with
`core.fsmonitor` and hooks disabled, so even a booby-trapped repository can't make it execute anything.
It reports **DANGER** only for specific evidence of the campaign (which blocks clones and pushes) and **WARNING**
for things that are unusual but can be legitimate (shown, never blocks). → [Full details](docs/checkrepo.md)

## 📊 Accuracy

The scanner was built from **real malware files** taken from an actual infection, then tuned against clean code:

| Test | Result |
|---|---|
| Real malware files (both payload variants, fake fonts, auto-run tasks, droppers) | **71 / 71 detected** |
| Same files with every known marker switched off — behaviour rules only | **71 / 71 detected** |
| 18 popular open-source projects — 106,225 files (Font-Awesome, Babel, Webpack, Prettier, javascript-obfuscator, VS Code samples…) | **0 false alarms** |
| A developer's 14 real projects + all installed packages — ~240,000 files | **0 false alarms** · 1 real infection leftover found |
| Self-test suite, incl. a code-execution safety test ([`scanner/tests`](scanner/tests)) | **51 / 51**, run on macOS, Linux and Windows in CI |
| Independent review — scripts tested in a sandbox; every finding fixed and covered by a test | ✅ |

**Honest limits:** the kit targets this family of attacks — a completely new technique may not be detected, which is
why it also hardens your editor, npm, git and GitHub and checks daily. The Windows scripts are beta: the scanner is
tested on Windows in CI, the installers still need real-world reports. A scan can't prove a machine is clean after a
backdoor has run — see the [recovery guide](docs/after-a-scan/if-danger-found.md).

## 📁 Repository structure

```
polinrider-survival-kit/
├── scan-my-machine.sh / .ps1   one-command, read-only machine scan
├── docs/                       every guide
│   ├── story/                  how I was attacked three times, and what finally worked
│   ├── attacks/                each attack explained, with sources
│   ├── after-a-scan/           incident response, GitHub cleanup, secrets, hardening
│   └── checkrepo.md · daily-routine.md · infected-packages.md
├── scanner/                    detection code: checkrepo, package checker, package lists, git hooks, safe clone, tests
├── mac/                        install / uninstall / daily check for macOS and Linux
└── windows/                    the same for Windows (beta)
```

## 📚 Learn more

- [The attacks](docs/attacks) — PolinRider worm, fake job interviews, BeaverTail / InvisibleFerret stealers, the MicrosoftSystem64
  backdoor, VS Code auto-run tasks, GlassWorm extensions, malicious npm packages, AI coding-agent attacks, ClickFix, EtherHiding
- [If you're infected](docs/after-a-scan/if-danger-found.md) · [Cleaning GitHub repositories](docs/after-a-scan/clean-github-repos.md) ·
  [Secrets rotation](docs/after-a-scan/secrets-rotation-checklist.md) · [Hardening checklist](docs/after-a-scan/hardening-checklist.md)

## 🤝 Contributing

Contributions are very welcome — especially **Windows test reports**, **new malicious packages or indicators**
(with a link to the public report), and **false-alarm reports**. Please read [CONTRIBUTING.md](CONTRIBUTING.md).
Fork the repository, create a branch, and open a pull request; every change needs a test.

Found a security problem in the kit itself? Please report it privately — see [SECURITY.md](SECURITY.md).

## 🙏 Credits

This kit stands on the work of researchers and other victims who published their findings:
[OpenSourceMalware](https://github.com/OpenSourceMalware/PolinRider) ·
[polinrider-cleaner](https://github.com/meSingh/polinrider-cleaner) (MIT — indicator lists) ·
[Bedri-B/polinrider](https://github.com/Bedri-B/polinrider) (MIT) ·
[pushwarden](https://github.com/FaheemRafiq/pushwarden) · [gitshield](https://github.com/mirzasaikatahmmed/gitshield) ·
Palo Alto Networks Unit 42 · Google Threat Intelligence Group · JFrog Security Research · Socket · Elastic Security Labs ·
Checkmarx · Cloud Security Alliance. Full source lists are at the end of every page in [`docs/attacks`](docs/attacks).

## ⚖️ License and disclaimer

[MIT](LICENSE) — use it, share it, adapt it.
This kit reduces risk; it cannot guarantee that a machine is clean or will stay clean. It is provided as-is, without warranty.
