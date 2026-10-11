"""Tests for the GitHub Action driver (scanner/ci.py). Offline: the GitHub check is replaced by a stand-in.
Run:  python3 scanner/tests/test_ci.py"""
import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
os.environ["ARDVANE_NO_FEED"] = "1"
import ci              # noqa: E402
import github_check    # noqa: E402

FAKE_FONT = "function _0x" + "3327(a){while(!![]){}}\n"      # JavaScript disguised as a font (assembled at runtime)


class Run(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ardvane-ci-")
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        self.summary, self.outputs = os.path.join(self.tmp, "summary.md"), os.path.join(self.tmp, "outputs")
        self.env = {"GITHUB_WORKSPACE": self.repo, "GITHUB_REPOSITORY": "me/demo", "GITHUB_STEP_SUMMARY": self.summary,
                    "GITHUB_OUTPUT": self.outputs, "ARDVANE_UPDATE": "false"}
        self.saved_env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved_env)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_ci(self, **env):
        os.environ.update(self.env, **env)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = ci.main()
        return code, out.getvalue()

    def infect(self):
        os.makedirs(os.path.join(self.repo, "public", "fonts"))
        with open(os.path.join(self.repo, "public", "fonts", "fa-solid-900.woff2"), "w") as f:
            f.write(FAKE_FONT)

    def test_clean_checkout(self):
        code, out = self.run_ci()
        self.assertEqual(code, 0)
        with open(self.outputs) as f:
            self.assertEqual(f.read(), "danger=0\nwarnings=0\n")
        with open(self.summary) as f:
            self.assertIn("No signs of malware", f.read())

    def test_malware_fails_the_job_and_marks_the_file(self):
        self.infect()
        code, out = self.run_ci()
        self.assertEqual(code, 1)
        self.assertIn("::error file=public/fonts/fa-solid-900.woff2,title=Ardvane::font file is actually JavaScript", out)
        with open(self.summary) as f:
            self.assertIn("Malware found", f.read())
        self.assertEqual(self.run_ci(ARDVANE_FAIL_ON="never")[0], 0)

    def test_fail_on_warning(self):
        os.makedirs(os.path.join(self.repo, ".vscode"))
        with open(os.path.join(self.repo, ".vscode", "settings.json"), "w") as f:
            f.write('{"task.allowAutomaticTasks": "on"}')
        self.assertEqual(self.run_ci()[0], 0)
        self.assertEqual(self.run_ci(ARDVANE_FAIL_ON="warning")[0], 1)

    def test_bad_inputs(self):
        self.assertEqual(self.run_ci(ARDVANE_MODE="everything")[0], 2)
        self.assertEqual(self.run_ci(ARDVANE_FAIL_ON="sometimes")[0], 2)
        self.assertEqual(self.run_ci(GITHUB_WORKSPACE=os.path.join(self.tmp, "missing"))[0], 2)
        self.assertEqual(self.run_ci(ARDVANE_MODE="all-branches", ARDVANE_REPOS="not a repo")[0], 2)

    def test_all_branches_uses_the_github_check(self):
        seen = {}

        def fake_check(user, rescan=False, repos=()):
            seen.update(user=user, rescan=rescan, repos=list(repos))
            return {"findings": [["DANGER", "me/demo (old-branch)", "public/fonts/x.woff2 - font file is actually JavaScript"]],
                    "listed": [{"repo": "me/demo", "outcome": "found", "branches": 3}], "notes": []}
        saved = github_check.check
        github_check.check = fake_check
        try:
            code, out = self.run_ci(ARDVANE_MODE="all-branches", ARDVANE_REPOS="https://github.com/org/other\nme/demo\n")
        finally:
            github_check.check = saved
        self.assertEqual(code, 1)
        self.assertEqual(seen, {"user": "", "rescan": True, "repos": ["me/demo", "org/other"]})
        self.assertIn("::error title=Ardvane%3A me/demo (old-branch)::public/fonts/x.woff2 - font file is actually JavaScript", out)


class Escaping(unittest.TestCase):
    def test_file_names_cannot_inject_workflow_commands(self):
        line = ci.annotation("error", "bad\n::add-mask::x", "Ardvane", "a,b:c\n::set-env name=X::1.js")
        self.assertEqual(line.count("\n"), 0)
        self.assertNotIn("\n::", line)
        self.assertEqual(line, "::error file=a%2Cb%3Ac%0A%3A%3Aset-env name=X%3A%3A1.js,title=Ardvane::bad%0A::add-mask::x")

    def test_markdown_cells(self):
        self.assertEqual(ci.md("a|b\nc<script>"), "a\\|b c&lt;script>")


if __name__ == "__main__":
    unittest.main(verbosity=2)
