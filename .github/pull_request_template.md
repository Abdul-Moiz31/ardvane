## What does this change?

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `python3 scanner/tests/run_tests.py` passes
- [ ] Dashboard changes: `python3 app/tests/test_backend.py` passes, and the dashboard was checked in light and dark mode
- [ ] New or changed detection rules have a **must-catch** and a **must-stay-quiet** test case (built at runtime — no real malware, marker strings assembled from pieces)
- [ ] New indicators / packages link to a public report
- [ ] `.ps1` files stay plain ASCII; shell scripts stay compatible with macOS's bash 3.2
- [ ] Docs updated if behaviour or commands changed
