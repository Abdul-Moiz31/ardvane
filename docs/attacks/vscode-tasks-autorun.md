# VS Code auto-run tasks (TasksJacker)

VS Code (and editors built on it: Cursor, Windsurf) supports **tasks** defined in a project's `.vscode/tasks.json`.
A task can be set to run automatically when the folder is opened (`"runOptions": { "runOn": "folderOpen" }`).
Attackers ship a hidden task that runs their loader — so **just opening the project runs the malware**.

## How it reaches you

- Cloning an infected repository, or a repository from a fake job test, and opening it in your editor.

## What it does

- The malicious task is labelled to look harmless (e.g. "eslint-check"), hidden (`"hide": true`, `"reveal": "never"`), and
  runs something like `node ./public/fonts/fa-solid-900.eot` — a fake font that is really JavaScript.
- A companion `.vscode/settings.json` sets `"task.allowAutomaticTasks": true` (or `"on"`) to skip the prompt that would
  otherwise ask you first.
- Variants download a script with `curl … | bash` or fetch from `*.vercel.app` hosts.

## How to spot it

- `.vscode/tasks.json` containing `folderOpen` together with `node` running a font / image / data file, a fonts folder, or a download.
- `.vscode/settings.json` turning on automatic tasks or turning off Workspace Trust.

## How to protect yourself

- In your **user** settings: `"task.allowAutomaticTasks": "off"` — then no folder can auto-run tasks.
- Keep **Workspace Trust** on and open unknown projects in **Restricted Mode** (no tasks, no debug configs, limited extensions).
- The kit's installer sets both, and `checkrepo` flags malicious auto-run tasks.
- Legit projects also use auto-start tasks (watchers, dev servers) — `checkrepo` only raises DANGER when the task runs a loader.

## Sources

1. Visual Studio Code docs — Workspace Trust: https://code.visualstudio.com/docs/editor/workspace-trust
2. Visual Studio Code docs — Tasks (run behavior / `runOn`): https://code.visualstudio.com/docs/editor/tasks
3. OpenSourceMalware — PolinRider dossier (TasksJacker vector, C2 hosts): https://github.com/OpenSourceMalware/PolinRider
4. OpenSourceMalware — "A Developer's Guide to Getting Rid of PolinRider" (VS Code settings advice): https://opensourcemalware.com/blog/developer-guide-getting-over-polinrider
5. Bedri-B/polinrider — VS Code autorun detection (MIT): https://github.com/Bedri-B/polinrider
