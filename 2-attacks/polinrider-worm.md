# PolinRider — the GitHub repository worm

**PolinRider** is a supply-chain campaign attributed by researchers to North Korea's Lazarus group (linked to the
"Contagious Interview" and "TasksJacker" activity). It hides obfuscated JavaScript loaders inside ordinary-looking
project files, steals the developer's credentials, and then **force-pushes the same loader into every repository and
branch the stolen access can reach** — including collaborators' and organizations' repos. Researchers report hundreds
of affected repositories and owners, and later spread to npm, Packagist, Go modules, PyPI projects and browser extensions.

## How it reaches you

- Cloning or pulling a repository that's already infected — often a collaborator's or a fork.
- A collaborator's infected machine pushing to a repo you share (it amends their commits automatically).
- Malicious or compromised packages (npm typosquats, hijacked Packagist packages).
- First infections typically come from fake job tests or fake packages (see the other pages).

## What it does

- **Appends an obfuscated loader to build config files** (`postcss.config.*`, `tailwind.config.*`, `next.config.*`,
  `vite.config.*`, `eslint.config.*`, `babel.config.*`, `jest.config.*`…) after a long run of spaces, so it's off-screen
  in editors and diffs. Because these files are executed by your build tools, the loader runs on `npm run dev` / build.
- **Drops fake fonts** — files named like Font Awesome (`fa-solid-400.woff2`, `fa-solid-900.woff2`, `.eot`; a later
  variant uses `.llf`) that are actually JavaScript, often next to a real-looking decoy Font Awesome bundle.
- **Adds `.vscode/tasks.json`** with a hidden task (`"runOn": "folderOpen"`) that runs the fake font with `node` the moment
  the folder is opened in VS Code / Cursor / Windsurf, plus `.vscode/settings.json` that turns automatic tasks on.
- **Adds an `api.js` dropper** (the October 2026 variant puts a hex-array loader in a root `api.js` and chains it into a
  `package.json` script, e.g. `"dev": "node api.js && …"`).
- **Rewrites history to hide**: amends the latest commit (keeping its date and author) and force-pushes to every branch.
  On Windows, helper files `temp_auto_push.bat` / `temp_interactive_push.bat` / `config.bat` do the pushing, and
  `.gitignore` entries hide them.
- **Fetches its next stage** from addresses stored on blockchains (TRON, Aptos, BSC) — see [EtherHiding](etherhiding-blockchain-c2.md).

## How to spot it

- Many repos updated within minutes of each other, at a time you weren't working; failed CI / deployments you didn't trigger.
- Config files that are suddenly kilobytes long, or whose last line scrolls far to the right.
- Markers inside files: `global['!']='…'`, `global['_V']=`, `global.i = 'A…'`, `_$_1e42`, `rmcej%otb%`, `Cot%3t=shtP`, `function MDy(`.
- Font files that open as text; `.vscode/tasks.json` with `folderOpen` running `node` on a font; `.gitignore` listing
  `temp_auto_push.bat`, `temp_interactive_push.bat`, `config.bat`, `branch_structure.json`.

## How to protect yourself

- Scan before you open: `checkrepo <folder>` — and let this kit's **git hooks** and **safe clone** do it automatically ([`../3-checkrepo`](../3-checkrepo)).
- VS Code / Cursor: automatic tasks **off**, Workspace Trust **on** (the kit's installer sets this).
- GitHub **rulesets**: block force-pushes on all branches and require signed commits — even a stolen token then can't rewrite your history.
- If you're infected: [`../6-after-a-scan/if-danger-found.md`](../6-after-a-scan/if-danger-found.md) — cut off access *before* cleaning.

## Timeline (as reported)

- **2026:** OpenSourceMalware publishes its PolinRider dossier and reports hundreds of compromised repositories, then
  expansion ("rides again"), and the spread to Go, Packagist, npm and PyPI.
- **April 2026:** a second marker/obfuscation variant (`global['_V']='8-…'`) is documented in the dossier.
- **September–October 2026:** community tools add the `.llf` fake-font variant, the root `api.js` + script-chain variant,
  and weekly indicator updates.

## Sources

1. OpenSourceMalware — PolinRider technical dossier (GitHub): https://github.com/OpenSourceMalware/PolinRider
2. OpenSourceMalware — "Hundreds of GitHub Repos Compromised By DPRK's PolinRider Campaign": https://opensourcemalware.com/blog/polinrider-dprk-compromised-hundreds-of-github-repos
3. OpenSourceMalware — "PolinRider DPRK Attack Expands Across GitHub": https://opensourcemalware.com/blog/polinrider-rides-again
4. OpenSourceMalware — "A Developer's Guide to Getting Rid of PolinRider": https://opensourcemalware.com/blog/developer-guide-getting-over-polinrider
5. OpenSourceMalware — "PolinRider Jumps the Fence to Go, Packagist, npm, PyPI": https://opensourcemalware.com/blog/polinrider-jumps-the-fence
6. OpenSourceMalware — "Popular Development Framework Neutralinojs Compromised In DPRK Attack": https://opensourcemalware.com/blog/neutralinojs-compromise
7. Bedri-B/polinrider — scanner and October 2026 variant notes (MIT): https://github.com/Bedri-B/polinrider
8. polinrider-cleaner — community indicator lists (MIT): https://github.com/meSingh/polinrider-cleaner
9. DEV Community — "Your GitHub Repositories Were Force-Pushed Overnight. Here's What to Do": https://dev.to/thisisroushan/your-github-repositories-were-force-pushed-overnight-heres-what-to-do-1o4p
