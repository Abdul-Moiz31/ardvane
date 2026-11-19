"""Tests for history.py: scanning every commit, and cleaning malware out of the history.  Run: python3 scanner/tests/test_history.py

Each test builds throw-away git repositories (a local "GitHub" bare repository included). Synthetic samples only.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

SANDBOX = os.path.realpath(tempfile.mkdtemp(prefix="history-test-"))
os.environ["HOME"] = os.environ["USERPROFILE"] = SANDBOX
os.environ["ARDVANE_NO_FEED"] = "1"
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import history  # noqa: E402

G_BANG = "global['" + "!']='9-6489-1';"
OBF = "function _0x" + "3327(_0x439fc1,_0x1bf3f1){while(!![]){}}"
CONFIG = "module.exports = {\n  content: ['./src/**/*.js'],\n};\n"
ENV = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
           GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")


def git(cwd, *args):
    r = subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "init.defaultBranch=main"] + list(args),
                       cwd=cwd, capture_output=True, text=True, env=ENV)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def write(root, files):
    for rel, text in files.items():
        p = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write(text)


def show(repo, ref, path):
    r = subprocess.run(["git", "--git-dir", repo, "show", f"{ref}:{path}"], capture_output=True, text=True, env=ENV)
    return r.stdout if r.returncode == 0 else None


class History(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(dir=SANDBOX)
        self.work = os.path.join(self.root, "work")
        os.makedirs(self.work)
        git(self.work, "init", "-q")
        write(self.work, {"tailwind.config.js": CONFIG, "src/index.js": "console.log('shop');\n", ".gitignore": "node_modules\n",
                          "package.json": json.dumps({"name": "shop", "scripts": {"dev": "next dev"}}, indent=2) + "\n"})
        git(self.work, "add", "-A"); git(self.work, "commit", "-qm", "first")
        self.first = git(self.work, "rev-parse", "HEAD")
        git(self.work, "branch", "feature")
        # the worm's commit: injected config, fake font, its .gitignore lines, a preinstall loader
        write(self.work, {"tailwind.config.js": CONFIG.replace("};\n", "};" + " " * 180 + G_BANG + "x" * 900 + "\n"),
                          "public/fonts/fa-solid-900.woff2": OBF + "\n", ".gitignore": "node_modules\ntemp_auto_" + "push.bat\n",
                          "package.json": json.dumps({"name": "shop", "scripts": {"preinstall": "node setup_" + "bun.js", "dev": "next dev"}}, indent=2) + "\n"})
        git(self.work, "add", "-A"); git(self.work, "commit", "-qm", "update deps")
        git(self.work, "tag", "-a", "v1", "-m", "release")
        # your own work after the infection
        write(self.work, {"src/app.js": "export const app = 1;\n"})
        git(self.work, "add", "-A"); git(self.work, "commit", "-qm", "my work")
        # an infected side branch
        git(self.work, "checkout", "-q", "feature")
        write(self.work, {".vscode/tasks.json": json.dumps({"tasks": [{"label": "x", "command": "node public/fonts/a.woff2",
                                                                         "runOptions": {"runOn": "folderOpen"}}]})})
        git(self.work, "add", "-A"); git(self.work, "commit", "-qm", "editor setup")
        git(self.work, "checkout", "-q", "main")
        self.origin = os.path.join(self.root, "origin.git")                 # stands in for the GitHub repository
        git(self.root, "clone", "-q", "--bare", self.work, self.origin)

    def test_scan_finds_malware_in_old_commits_branches_and_tags(self):
        res = history.scan(self.work)
        rules = {(f["rule"], f["path"]) for f in res["findings"]}
        self.assertIn(("fake-font", "public/fonts/fa-solid-900.woff2"), rules)
        self.assertIn(("vscode-autorun", ".vscode/tasks.json"), rules, "a branch nobody opens is checked too")
        self.assertIn(("gitignore-worm", ".gitignore"), rules)
        self.assertIn(("worm-loader", "package.json"), rules)
        font = next(f for f in res["findings"] if f["rule"] == "fake-font")
        self.assertIn("v1", font["refs"])
        self.assertIn("main", font["live_refs"], "the font is in main's current files")
        self.assertIn("current files", font["where"])

    def test_malware_removed_later_is_reported_as_history_only(self):
        write(self.work, {"public/fonts/fa-solid-900.woff2": "", "src/app.js": "export const app = 2;\n"})
        os.remove(os.path.join(self.work, "public", "fonts", "fa-solid-900.woff2"))
        git(self.work, "add", "-A"); git(self.work, "commit", "-qm", "remove font")
        fixed = git(self.work, "rev-parse", "--short=10", "HEAD")
        font = next(f for f in history.scan(self.work)["findings"] if f["rule"] == "fake-font")
        self.assertEqual(font["live_refs"], ["v1"], "the tag still points at the infected commit")
        git(self.work, "tag", "-d", "v1")
        font = next(f for f in history.scan(self.work)["findings"] if f["rule"] == "fake-font")
        self.assertEqual(font["live_refs"], [])
        self.assertIn(fixed, font["removed_in"])
        self.assertIn("only in older commits", font["where"])

    def test_a_clean_history_has_no_findings(self):
        clean = os.path.join(self.root, "clean")
        os.makedirs(clean)
        git(clean, "init", "-q")
        write(clean, {"src/a.js": "export default 1;\n", "package.json": "{\"name\": \"a\"}\n"})
        git(clean, "add", "-A"); git(clean, "commit", "-qm", "a")
        self.assertEqual(history.scan(clean)["findings"], [])

    def test_clean_rewrites_every_branch_and_tag_and_keeps_your_work(self):
        plan = history.clean("me/shop", remote=self.origin, check_owner=False)
        self.assertEqual(plan["state"], "ready", plan.get("left"))
        repo = os.path.join(plan["workdir"], "clean.git")
        self.assertEqual(history.scan_git_dir(repo)["findings"], [], "nothing malicious is left anywhere in the history")
        self.assertEqual(show(repo, "refs/heads/main", "tailwind.config.js"), CONFIG, "the config is exactly what it was")
        self.assertEqual(show(repo, "refs/heads/main", "src/app.js"), "export const app = 1;\n", "your later work stays")
        self.assertIsNone(show(repo, "refs/heads/main", "public/fonts/fa-solid-900.woff2"))
        self.assertEqual(show(repo, "refs/heads/main", ".gitignore"), "node_modules\n")
        self.assertEqual(json.loads(show(repo, "refs/heads/main", "package.json"))["scripts"], {"dev": "next dev"})
        self.assertIsNone(show(repo, "refs/heads/feature", ".vscode/tasks.json"))
        self.assertEqual(show(repo, "refs/tags/v1", "tailwind.config.js"), CONFIG, "tags are rewritten too")
        self.assertEqual(git(self.root, "--git-dir", repo, "rev-list", "--count", "refs/heads/main"), "3", "no commit is lost")
        self.assertTrue(os.path.isdir(os.path.join(plan["workdir"], "backup.git")))
        self.assertEqual(git(self.root, "--git-dir", self.origin, "rev-parse", "refs/heads/main"),
                         plan["before"]["refs/heads/main"], "nothing is pushed before a person confirms")

    def test_push_updates_github_and_refuses_if_someone_pushed_meanwhile(self):
        plan = history.clean("me/shop", remote=self.origin, check_owner=False)
        pushed = history.push(plan["workdir"])
        self.assertTrue(pushed["pushed"])
        self.assertEqual(git(self.root, "--git-dir", self.origin, "rev-parse", "refs/heads/main"), plan["after"]["refs/heads/main"])
        self.assertEqual(history.scan_git_dir(self.origin)["findings"], [], "the repository's history is clean now")
        with self.assertRaises(ValueError):
            history.push(plan["workdir"])                                   # can't push the same plan twice

    def test_push_is_refused_when_the_repository_changed_after_preparing(self):
        plan = history.clean("me/shop", remote=self.origin, check_owner=False)
        write(self.work, {"src/late.js": "1;\n"})
        git(self.work, "add", "-A"); git(self.work, "commit", "-qm", "late")
        git(self.work, "push", "-q", self.origin, "main")                   # someone pushes in the meantime
        with self.assertRaises(RuntimeError):
            history.push(plan["workdir"])
        self.assertIn("late", git(self.root, "--git-dir", self.origin, "log", "--format=%s", "-1", "main"), "their push is untouched")

    def test_nothing_to_clean(self):
        clean_origin = os.path.join(self.root, "clean.git")
        git(self.root, "clone", "-q", "--bare", self.work, clean_origin)
        git(self.root, "--git-dir", clean_origin, "update-ref", "refs/heads/main", self.first)
        git(self.root, "--git-dir", clean_origin, "update-ref", "-d", "refs/heads/feature")
        git(self.root, "--git-dir", clean_origin, "tag", "-d", "v1")
        plan = history.clean("me/clean", remote=clean_origin, check_owner=False)
        self.assertEqual(plan["state"], "nothing-to-clean")

    def test_other_peoples_repositories_are_refused(self):
        history.can_administer = lambda name: False
        with self.assertRaises(PermissionError):
            history.clean("someone/else")
        with self.assertRaises(ValueError):
            history.clean("not a repo name")


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        shutil.rmtree(SANDBOX, ignore_errors=True)
