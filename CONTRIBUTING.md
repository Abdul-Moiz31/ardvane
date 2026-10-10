# Contributing

Thank you for helping other developers stay safe.

## Most useful contributions

- **Windows test results** — run the Windows installer and daily check, and open an issue with what worked and what didn't.
- **New malicious packages / indicators** — add them to `5-infected-packages/*.txt` or the indicator lists in
  `3-checkrepo/checkrepo.py`, **with a link to the public report**.
- **False alarms** — open an issue with the file type and the rule that fired (please don't paste secrets or private code).
- **Missed detections** — describe the technique and link the research. **Never upload real malware** — describe it,
  or share a hash and a public reference.

## Rules for changes to the scanner

1. Every new rule needs a **must-catch** case and at least one **must-stay-quiet** case in `3-checkrepo/tests/run_tests.py`.
   Build test samples at runtime and assemble marker strings from pieces, so the repo never contains literal payloads.
2. Run `python3 3-checkrepo/tests/run_tests.py` — all cases must pass.
3. Prefer **WARNING** over **DANGER** unless the evidence is specific to the campaign: DANGER blocks clones and pushes,
   so a false DANGER breaks people's work.
4. Keep `checkrepo.py` dependency-free and read-only.

## Reporting a problem in the kit itself

If you find a security issue in the kit (for example a way to make it run code), please report it privately first
via GitHub's "Report a vulnerability" (Security tab) rather than in a public issue.
