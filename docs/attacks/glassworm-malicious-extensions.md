# GlassWorm — malicious editor extensions

**GlassWorm** is a campaign of malicious VS Code-compatible extensions published mainly on the **Open VSX**
registry (used by Cursor, Windsurf, VSCodium and others). Extensions impersonate popular tools — linters, formatters,
code runners, AI assistants — and some hide their code in **invisible Unicode characters**, so a human reviewer sees
nothing. Researchers reported 72+ and later 73 malicious extensions in 2026.

## How it reaches you

- Installing a look-alike extension, or an extension that later **updates** to pull in a malicious one through
  `extensionPack` / `extensionDependencies` (it looked clean when you installed it).

## What it does

- Runs with your editor's permissions: can read your files and tokens and run commands.
- Uses staged loaders rebuilt at runtime to avoid detection.

## How to spot it

- Extensions from unknown publishers, recently published, with few reviews, cloning a well-known extension's name.
- An extension that suddenly adds dependencies on other extensions after an update.
- Long runs of invisible characters in source files (`checkrepo` flags these).

## How to protect yourself

- Install only from verified publishers with a real history; keep your extension list short; review it now and then.
- The kit's daily check lists extensions installed or updated in the last 24 hours so you notice surprises.

## Sources

1. Socket — "72 Malicious Open VSX Extensions Linked to GlassWorm Campaign": https://socket.dev/blog/open-vsx-transitive-glassworm-campaign
2. The Hacker News — "GlassWorm Supply-Chain Attack Abuses 72 Open VSX Extensions to Target Developers" (March 2026): https://thehackernews.com/2026/03/glassworm-supply-chain-attack-abuses-72.html
3. The Hacker News — "Researchers Uncover 73 Fake VS Code Extensions Delivering GlassWorm v2 Malware" (April 2026): https://thehackernews.com/2026/04/researchers-uncover-73-fake-vs-code.html
4. Checkmarx Zero — "GlassWorm Malware Targets Developer IDEs Again": https://checkmarx.com/zero-post/glassworm-targets-developer-ides-again-hiding-staged-malware-behind-runtime-rebuilt-loaders/
