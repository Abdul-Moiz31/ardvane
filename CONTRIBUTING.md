# Contributing

Thank you for helping other developers stay safe.

## Most useful contributions

- **Windows test results** — run the Windows installer and daily check, and open an issue with what worked and what didn't.
- **New malicious packages / indicators** — add them to `scanner/lists/*.txt` or the indicator lists in
  `scanner/checkrepo.py`, **with a link to the public report**.
- **False alarms** — open an issue with the file type and the rule that fired (please don't paste secrets or private code).
- **Missed detections** — describe the technique and link the research. **Never upload real malware** — describe it,
  or share a hash and a public reference.

## Rules for changes to the scanner

1. Every new rule needs a **must-catch** case and at least one **must-stay-quiet** case in `scanner/tests/run_tests.py`.
   Build test samples at runtime and assemble marker strings from pieces, so the repo never contains literal payloads.
2. Run `python3 scanner/tests/run_tests.py` — all cases must pass.
3. Prefer **WARNING** over **DANGER** unless the evidence is specific to the campaign: DANGER blocks clones and pushes,
   so a false DANGER breaks people's work.
4. Keep `checkrepo.py` dependency-free and read-only.
5. `github_check.py` changes need an offline test in `scanner/tests/test_github_check.py` (never call the network in tests).

## Rules for changes to the dashboard (`app/`)

1. No dependencies: Python standard library in `app/backend/`, plain JavaScript modules in `app/ui/` (no npm, no
   build step, no CDN). Add `// @ts-check` and JSDoc types to JavaScript files; CI type-checks them.
2. Never insert data into the page as HTML — build elements with `h()` from `ui/js/dom.js`.
3. Every API input is validated on the server, and security checks get a test in `app/tests/test_backend.py`.
4. The dashboard never changes the system itself: it calls the kit's reviewed scripts in `mac/` and `windows/`.
5. Keep one responsibility per module, and put shared helpers in one place instead of copying them.

## Releasing

Releases are automatic. In a pull request, raise `VERSION` in `app/backend/config.py` (semantic versioning: `0.1.1` for
fixes, `0.2.0` for new features) and add a `## <version>` section to `CHANGELOG.md`. CI fails if the version has no
notes. When the pull request is merged and the tests pass on `main`, `.github/workflows/release.yml` tags the commit
`v<version>`, publishes the release with those notes and uploads the package to PyPI (`pipx install ardvane`); the
Homebrew tap ([abdul-moiz31/homebrew-ardvane](https://github.com/Abdul-Moiz31/homebrew-ardvane)) picks the release up by
itself within a few hours. Merges that don't change the version publish nothing.

## Reporting a problem in the kit itself

If you find a security issue in the kit (for example a way to make it run code), please report it privately first
via GitHub's "Report a vulnerability" (Security tab) rather than in a public issue.
