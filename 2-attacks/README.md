# The attacks — what you're defending against

Every file explains one attack in plain language: how it reaches you, what it does, how to spot it, how to
protect yourself, and the research it's based on (with links).

| Attack | How it reaches you | What it does | Read |
|---|---|---|---|
| **PolinRider worm** | Stolen GitHub access, infected collaborators, infected packages | Hides loaders in config files, fake fonts and VS Code tasks; force-pushes itself into every repo it can reach | [polinrider-worm.md](polinrider-worm.md) |
| **Contagious Interview (fake jobs)** | Fake recruiters, take-home coding tests | Runs the first-stage malware when you run the "test" | [contagious-interview-fake-jobs.md](contagious-interview-fake-jobs.md) |
| **BeaverTail / InvisibleFerret stealers** | Delivered by the two above | Steal browser passwords & cookies, Keychain, crypto wallets, files; remote control | [beavertail-invisibleferret-stealers.md](beavertail-invisibleferret-stealers.md) |
| **MicrosoftSystem64 implant** | Malicious npm package (`js-logger-pack`) and later stages | Cross-platform remote-access backdoor that disguises itself as a system service | [microsoftsystem64-implant.md](microsoftsystem64-implant.md) |
| **VS Code auto-run tasks (TasksJacker)** | A repo with `.vscode/tasks.json` | Runs code the moment you open the folder | [vscode-tasks-autorun.md](vscode-tasks-autorun.md) |
| **GlassWorm extensions** | Fake / hijacked editor extensions | Hidden code (even invisible Unicode) inside extensions | [glassworm-malicious-extensions.md](glassworm-malicious-extensions.md) |
| **Malicious npm packages** | Typosquats, fake company SDKs | Install scripts that download and run malware | [malicious-npm-packages.md](malicious-npm-packages.md) |
| **AI coding-agent attacks** | `CLAUDE.md`, `AGENTS.md`, `.mcp.json`, agent hooks in a repo | Turn your AI assistant into the attacker's helper | [ai-agent-config-attacks.md](ai-agent-config-attacks.md) |
| **ClickFix** | Fake meeting / "fix your camera" pages, malicious ads | You paste a command that installs malware | [clickfix-fake-meeting-fix.md](clickfix-fake-meeting-fix.md) |
| **EtherHiding (blockchain C2)** | Used inside the loaders | Hides the attacker's server address on a blockchain | [etherhiding-blockchain-c2.md](etherhiding-blockchain-c2.md) |

## How they connect

1. **Getting in:** a fake job test, a fake package, a fake extension, a pasted command — or a collaborator who was already infected.
2. **First stage:** a small JavaScript loader runs (often automatically: install script, VS Code task, imported config file).
3. **Second stage:** it fetches the real malware — the address is often read from a blockchain so it can't simply be blocked.
4. **Stealing:** browser data, keys, tokens, wallets are taken; a backdoor keeps access.
5. **Spreading:** with your GitHub access the worm plants the loader in your repos and your collaborators' repos —
   and the next person who opens one starts again at step 2.

That loop is why cleaning only your laptop, or only your repos, doesn't stop it. See [`../6-after-a-scan`](../6-after-a-scan).

> These pages summarise public research as of October 2026. The campaigns change constantly; always check the linked sources for updates.
