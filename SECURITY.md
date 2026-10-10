# Security policy

## Reporting a vulnerability in the kit

If you find a way to make the kit itself unsafe — for example a way for a scanned repository to make `checkrepo`
execute code, a bypass of the git hooks or safe clone, or anything in the installers that could damage a user's
system — **please report it privately**:

- Use GitHub's **[Report a vulnerability](https://github.com/Abdul-Moiz31/polinrider-survival-kit/security/advisories/new)** button (Security tab → Advisories), or
- open a minimal public issue saying "security report — please enable a private channel" without details.

Please include what you did, what happened, and the operating system / Python version. I'll acknowledge reports as
quickly as I can and credit you in the fix unless you prefer otherwise.

## Reporting malware, packages or indicators

New malicious packages, infected repositories or indicators of compromise aren't vulnerabilities in the kit — please
open a normal issue or pull request **with a link to a public report**. Never upload real malware samples; share a
SHA-256 hash and a public reference instead.

## Scope

- `scanner/` (scanner, fixer, hooks, safe clone, lists) — a way to make `autofix.py` move or change something outside its rules is in scope, `mac/` and `windows/` (installers, daily routine), `app/`, `scan-my-machine.*`
- The guides are best-effort advice; corrections are welcome as normal issues.
