# Infected packages

Lists of package names that researchers have confirmed as malicious or compromised in the PolinRider /
Contagious Interview campaigns.

| File | Ecosystem | Count |
|---|---|---|
| [`npm.txt`](npm.txt) | npm (JavaScript) — typosquats of Tailwind / PostCSS / Vite add-ons, fake logger packages, fake company SDKs | 84 |
| [`pypi.txt`](pypi.txt) | Python package names reported alongside them | 2 |
| [`packagist.txt`](packagist.txt) | Packagist (PHP) packages compromised through hijacked maintainer accounts | 10 |

Researchers also report **more than 80 compromised Go modules** and several Python projects, but without a
clean list of names, so they are not included here — see the sources in each file.

## Check your projects

```bash
python3 check-my-projects.py                 # scans Documents, Desktop, Downloads, ~/code, ~/projects, source/repos
python3 check-my-projects.py ~/work ~/side   # or specific folders
```

It reads `package.json`, lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`),
`requirements.txt` / `pyproject.toml` / `poetry.lock` / `uv.lock`, `composer.json` / `composer.lock`, the names of
installed `node_modules` folders and your **global** npm packages. It never installs or runs anything.
Look-alike names are not matched (for example `tailwind-merge` is fine; `tailwindcss-merge` is on the list).

`checkrepo` (in `../3-checkrepo`) uses the same npm list automatically on every clone / pull / push.

## Important: a list is never complete

New malicious packages appear every week. Being on no list doesn't make a package safe. Before adding a dependency:

- Check the exact name, publisher and weekly downloads on the registry page — typosquats are usually brand-new with few downloads.
- Prefer packages linked from the official docs of the tool you're using.
- Keep `npm config set ignore-scripts true` (installed by the kit) so a bad package can't run code at install time.
- One victim of this campaign was hit by a **fake npm package impersonating a real company's SDK** — when an SDK
  comes from a vendor, install the exact package name from the vendor's own documentation.

## Sources and credit

- polinrider-cleaner — `ioc/bad-packages.txt` (MIT): https://github.com/meSingh/polinrider-cleaner
- Bedri-B/polinrider (MIT): https://github.com/Bedri-B/polinrider
- OpenSourceMalware — PolinRider dossier: https://github.com/OpenSourceMalware/PolinRider
- OpenSourceMalware — "PolinRider Jumps the Fence to Go, Packagist, npm, PyPI": https://opensourcemalware.com/blog/polinrider-jumps-the-fence
- Socket — North Korean Contagious Interview campaign malicious npm packages: https://socket.dev/blog/north-korean-contagious-interview-campaign-drops-35-new-malicious-npm-packages

Found a new one? Open a pull request adding it with a link to the public report.
