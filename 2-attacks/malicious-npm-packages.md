# Malicious npm packages

The campaigns publish packages whose names look like popular libraries (**typosquats** of Tailwind, PostCSS, Vite
plugins, loggers…) or like a real company's SDK. The malware usually starts from an **install script**
(`preinstall` / `postinstall`), which npm runs automatically during `npm install`.

## How it reaches you

- Adding a dependency by a slightly wrong name, or one suggested by a stranger, a "test project" or an AI answer.
- A fake package pretending to be a vendor's official SDK (this happened to the author of this kit).
- A legitimate-looking package that depends on a malicious one.

## What it does

- The install script downloads and runs the next stage in the background (for example the
  [MicrosoftSystem64](microsoftsystem64-implant.md) backdoor from `js-logger-pack`), while the install finishes normally.
- Some packages hide loaders in the files your build imports.

## How to spot it

- Names close to a popular package (`tailwindcss-animate-style` vs `tailwindcss-animate`), new packages with few downloads.
- Install scripts that pipe a download into a shell, decode base64, or start detached processes.
- Compare your dependencies with the known list: [`../5-infected-packages`](../5-infected-packages).

## How to protect yourself

- `npm config set ignore-scripts true` — install scripts can't run (the kit sets this). Re-enable per trusted project if needed:
  `npm install --ignore-scripts=false`.
- Install SDKs by the exact name in the vendor's docs; check the registry page (publisher, downloads, repository link).
- Commit and review lockfiles; `checkrepo` checks lockfiles against the known-bad list on every clone / pull / push.

## Sources

1. npm Docs — config (`ignore-scripts`): https://docs.npmjs.com/cli/v10/using-npm/config
2. Socket — North Korean Contagious Interview campaign malicious npm packages: https://socket.dev/blog/north-korean-contagious-interview-campaign-drops-35-new-malicious-npm-packages
3. The Hacker News — "North Korean Hackers Publish 108 Malicious Packages and Extensions in PolinRider Campaign" (July 2026): https://thehackernews.com/2026/07/north-korean-hackers-publish-108.html
4. OpenSourceMalware — "PolinRider Jumps the Fence to Go, Packagist, npm, PyPI": https://opensourcemalware.com/blog/polinrider-jumps-the-fence
5. JFrog Security Research — js-logger-pack: https://research.jfrog.com/post/hugging-face-exfil/
6. polinrider-cleaner — `ioc/bad-packages.txt` (MIT): https://github.com/meSingh/polinrider-cleaner
