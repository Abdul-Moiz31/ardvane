"""Tests for the global git hook dispatcher (scanner/hooks/dispatch), run against throwaway repositories in a
temporary HOME, so your own git configuration is never touched.  Run:  python3 scanner/tests/test_hooks.py
Needs git and bash (skipped otherwise). Payloads are assembled at runtime; this file holds no malware markers."""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
KIT_SCANNER = os.path.join(HERE, "..")
FAKE_FONT = "function _0x" + "3327(a){while(!![]){}}\n"     # JavaScript disguised as a font


@unittest.skipUnless(shutil.which("git") and shutil.which("bash") and os.name != "nt", "needs git and bash")
class PrePush(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ardvane-hooks-")
        hooks = os.path.join(self.tmp, "hooks")
        os.makedirs(hooks)
        shutil.copy(os.path.join(KIT_SCANNER, "hooks", "dispatch"), os.path.join(hooks, "dispatch"))
        os.chmod(os.path.join(hooks, "dispatch"), 0o755)          # the installer does this too
        for name in ("pre-push", "post-checkout"):
            os.symlink("dispatch", os.path.join(hooks, name))
        self.env = dict(os.environ, HOME=self.tmp, GIT_CONFIG_GLOBAL=os.path.join(self.tmp, "gitconfig"),
                        GIT_CONFIG_NOSYSTEM="1", CHECKREPO=os.path.join(KIT_SCANNER, "checkrepo.py"))
        for k, v in (("core.hooksPath", hooks), ("user.email", "t@t"), ("user.name", "t"), ("init.defaultBranch", "main"),
                     ("commit.gpgsign", "false")):
            self.git(self.tmp, "config", "--global", k, v)
        self.git(self.tmp, "init", "-q", "--bare", "remote.git")
        self.git(self.tmp, "clone", "-q", "remote.git", "work")
        self.work = os.path.join(self.tmp, "work")
        self.commit({"README.md": "hi\n"}, "init")
        self.git(self.work, "push", "-q", "origin", "main")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def git(self, cwd, *args):
        return subprocess.run(["git", *args], cwd=cwd, env=self.env, capture_output=True, text=True, timeout=120)

    def commit(self, files, msg):
        for rel, text in files.items():
            p = os.path.join(self.work, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(text)
        self.git(self.work, "add", "-A")
        self.git(self.work, "commit", "-qm", msg)

    def remote_has(self, branch):
        return bool(self.git(self.work, "ls-remote", "origin", branch).stdout.strip())

    def test_infected_branch_is_blocked_even_when_a_clean_branch_is_checked_out(self):
        self.git(self.work, "checkout", "-qb", "infected")
        self.commit({"public/fonts/fa-solid-900.woff2": FAKE_FONT}, "bad")
        self.git(self.work, "checkout", "-q", "main")
        r = self.git(self.work, "push", "origin", "infected")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("PUSH BLOCKED", r.stderr)
        self.assertIn("(being pushed)", r.stderr)          # names the commit, not a temporary folder
        self.assertFalse(self.remote_has("infected"))

    def test_untracked_files_do_not_block_an_unrelated_push(self):
        self.commit({"README.md": "more\n"}, "more")
        os.makedirs(os.path.join(self.work, "public", "fonts"))
        with open(os.path.join(self.work, "public", "fonts", "x.woff2"), "w") as f:   # on disk, never committed
            f.write(FAKE_FONT)
        r = self.git(self.work, "push", "origin", "main")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_repo_own_pre_push_hook_still_gets_the_ref_list(self):
        hook = os.path.join(self.work, ".git", "hooks", "pre-push")
        proof = os.path.join(self.tmp, "refs-seen")
        with open(hook, "w") as f:
            f.write('#!/bin/sh\ncat > "%s"\n' % proof)
        os.chmod(hook, os.stat(hook).st_mode | stat.S_IEXEC)
        self.commit({"README.md": "more\n"}, "more")
        self.assertEqual(self.git(self.work, "push", "origin", "main").returncode, 0)
        with open(proof) as f:
            self.assertIn("refs/heads/main", f.read())

    def test_branch_deletion_needs_no_scan(self):
        self.git(self.work, "push", "-q", "origin", "main:tmp")
        r = self.git(self.work, "push", "origin", ":tmp")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.remote_has("tmp"))

    def test_a_failing_scanner_warns_but_never_blocks(self):
        broken = os.path.join(self.tmp, "broken.py")
        with open(broken, "w") as f:
            f.write("import sys\nsys.exit(4)\n")
        self.env["CHECKREPO"] = broken
        self.commit({"README.md": "more\n"}, "more")
        r = self.git(self.work, "push", "origin", "main")
        self.assertEqual(r.returncode, 0)
        self.assertIn("NOT checked", r.stderr)

    def test_working_tree_and_index_are_untouched(self):
        with open(os.path.join(self.work, "notes.txt"), "w") as f:
            f.write("x\n")
        self.commit({"README.md": "more\n"}, "more")
        with open(os.path.join(self.work, "README.md"), "a") as f:
            f.write("uncommitted\n")
        self.git(self.work, "push", "-q", "origin", "main")
        self.assertEqual(sorted(self.git(self.work, "status", "--porcelain").stdout.split("\n")[:-1]),
                         [" M README.md"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
