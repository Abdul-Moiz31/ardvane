"""Offline tests for the four 0.12 tools: github_protect, report_owner, sandbox, credaudit.  Run:  python3 scanner/tests/test_tools.py"""
import importlib.util
import io
import json
import os
import contextlib
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(HERE, "..")
sys.path.insert(0, SCANNER)
SANDBOX_HOME = tempfile.mkdtemp(prefix="tools-home-")
os.environ["HOME"] = os.environ["USERPROFILE"] = SANDBOX_HOME


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(SCANNER, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gp = load("github_protect")
gc = gp.gc                      # the very module github_protect uses, so patching its paths works
ro = load("report_owner")
sb = load("sandbox")
ca = load("credaudit")


class FakeClient:
    """Answers GET from a dict and records every change; a missing path is a 404."""
    gh = "gh"
    truncated = []

    def __init__(self, answers, fail_on=None):
        self.answers, self.sent, self.fail_on = answers, [], fail_on

    def get(self, path, limit=0):
        if path not in self.answers:
            raise RuntimeError("HTTP 404: Not Found")
        return self.answers[path]

    def send(self, method, path, body=None):
        self.sent.append((method, path, body))
        if self.fail_on and self.fail_on in path:
            raise RuntimeError("Upgrade to GitHub Pro or make this repository public to enable this feature.")
        return {"id": 4242} if method == "POST" else {}


class ProtectBranches(unittest.TestCase):
    def setUp(self):
        self.files = (gp.RULESETS_FILE, gc.AUDIT_FILE)
        folder = tempfile.mkdtemp()
        gp.RULESETS_FILE, gc.AUDIT_FILE = os.path.join(folder, "rulesets.json"), os.path.join(folder, "audit.json")
        with open(gc.AUDIT_FILE, "w") as f:
            json.dump({"time": time.time(), "findings": [], "admin": 2, "notes": ["2 of 2 repositories you administer let a stolen token force-push the default branch"],
                       "exposed": [{"repo": "me/app", "branch": "main", "private": False}, {"repo": "me/api", "branch": "main", "private": True}]}, f)

    def tearDown(self):
        gp.RULESETS_FILE, gc.AUDIT_FILE = self.files

    def answers(self, admin=True, rules=()):
        return {"/repos/me/app": {"permissions": {"admin": admin}, "default_branch": "main"},
                "/repos/me/app/rules/branches/main": list(rules)}

    def test_the_ruleset_blocks_force_pushes_and_deletion_for_everyone(self):
        body = gp.ruleset_body()
        self.assertEqual([r["type"] for r in body["rules"]], ["non_fast_forward", "deletion"])
        self.assertEqual(body["bypass_actors"], [])
        self.assertEqual(body["enforcement"], "active")
        self.assertEqual(body["conditions"]["ref_name"]["include"], ["~DEFAULT_BRANCH"])

    def test_protecting_adds_one_ruleset_remembers_it_and_updates_the_open_list(self):
        c = FakeClient(self.answers())
        r = gp.protect_one(c, "me/app")
        self.assertEqual(r["status"], "protected")
        self.assertEqual([(m, p) for m, p, _ in c.sent], [("POST", "/repos/me/app/rulesets")])
        self.assertEqual(gp.protected()["me/app"]["id"], 4242)
        self.assertEqual([x["repo"] for x in gp.exposed()], ["me/api"])
        notes = json.load(open(gc.AUDIT_FILE))["notes"]
        self.assertTrue(any("1 of 2" in n and "me/api" in n for n in notes), notes)

    def test_undo_deletes_exactly_the_ruleset_ardvane_added(self):
        gp.protect_one(FakeClient(self.answers()), "me/app")
        c = FakeClient({})
        self.assertEqual(gp.undo_one(c, "me/app")["status"], "removed")
        self.assertEqual(c.sent, [("DELETE", "/repos/me/app/rulesets/4242", None)])
        self.assertEqual(gp.protected(), {})
        self.assertEqual(gp.undo_one(c, "me/app")["status"], "failed", "nothing left to undo")

    def test_it_never_changes_a_repository_you_dont_administer_or_that_is_already_protected(self):
        c = FakeClient(self.answers(admin=False))
        self.assertEqual(gp.protect_one(c, "me/app")["status"], "failed")
        c = FakeClient(self.answers(rules=[{"type": "non_fast_forward"}]))
        self.assertEqual(gp.protect_one(c, "me/app")["status"], "already")
        self.assertEqual(c.sent, [])

    def test_a_dry_run_changes_nothing_and_a_refusal_from_github_is_explained(self):
        c = FakeClient(self.answers())
        self.assertEqual(gp.protect_one(c, "me/app", dry_run=True)["status"], "dry-run")
        self.assertEqual(c.sent, [])
        r = gp.protect_one(FakeClient(self.answers(), fail_on="rulesets"), "me/app")
        self.assertEqual(r["status"], "failed")
        self.assertIn("paid GitHub plan", r["message"])
        self.assertEqual(gp.protected(), {}, "a failed attempt is not remembered")

    def test_bad_names_are_refused(self):
        with self.assertRaises(ValueError):
            gp.protect_one(FakeClient({}), "not a repo")


class Report(unittest.TestCase):
    FINDINGS = [["DANGER", "talent/test (main, shared with you)", ".vscode/tasks.json - runs a command when the folder opens"],
                ["DANGER", "talent/test (dev, shared with you)", ".vscode/tasks.json - runs a command when the folder opens"],
                ["WARNING", "talent/test (main, shared with you)", "package.json - install script"],
                ["DANGER", "talent/test (main, shared with you)", ".vscode/tasks.json - runs a command when the folder opens"]]

    def test_findings_are_grouped_per_file_and_reason_with_the_worst_first(self):
        rows = ro.group(self.FINDINGS)
        self.assertEqual(len(rows), 3, "the repeated finding is listed once")
        self.assertEqual([r[1] for r in rows], ["DANGER", "DANGER", "WARNING"])

    def test_the_report_says_what_where_and_what_to_do_and_names_nothing_of_this_computer(self):
        text = ro.build_report("talent/test", self.FINDINGS, public=False)
        for needle in ("# Malware found in talent/test", ".vscode/tasks.json", "What to do, in this order", "Block force pushes", "rewritten"):
            self.assertIn(needle, text)
        self.assertNotIn(SANDBOX_HOME, text)
        self.assertNotIn("public, so anyone", text)
        self.assertIn("public, so anyone", ro.build_report("talent/test", self.FINDINGS, public=True))

    def test_table_cells_cannot_break_out_of_the_table(self):
        text = ro.build_report("a/b", [["DANGER", "a/b (main)", "x|y.js - bad | worse\nnext line"]])
        row = [l for l in text.splitlines() if "x\\|y.js" in l][0]
        self.assertEqual(row.count("|") - row.count("\\|"), 4)


class Sandbox(unittest.TestCase):
    def test_targets_are_a_github_repo_or_an_existing_folder_only(self):
        self.assertEqual(sb.parse_target("owner/name"), ("github", "owner/name"))
        self.assertEqual(sb.parse_target("https://github.com/owner/name/tree/main"), ("github", "owner/name"))
        self.assertEqual(sb.parse_target(SANDBOX_HOME)[0], "folder")
        for bad in ("", "x y", "owner/name; rm -rf /", "--privileged", "./does-not-exist", "$(whoami)/x"):
            with self.assertRaises(ValueError, msg=bad):
                sb.parse_target(bad)

    def flat(self, steps):
        return [" ".join(argv) for _, argv in steps]

    def test_the_container_gets_nothing_of_this_computer(self):
        steps = sb.commands("docker", "github", "owner/name", "ardvane-sandbox-t", network=True)
        run = steps[0][1]
        text = " ".join(run)
        for forbidden in ("-v ", "--volume", "--mount", "--privileged", "docker.sock", "--env", " -e ", "--env-file", "--network host", "--pid ", "--pid=", "--device"):
            self.assertNotIn(forbidden, text)
        for required in ("--cap-drop ALL", "no-new-privileges", "--memory", "--pids-limit", "--rm"):
            self.assertIn(required, text)

    def test_the_target_is_an_argument_never_part_of_a_shell_string(self):
        steps = sb.commands("docker", "github", "owner/name", "n")
        clone = steps[1][1]
        self.assertEqual(clone[-1], "https://github.com/owner/name.git")
        self.assertNotIn("owner/name", clone[clone.index("-c") + 1], "the script only refers to $1")
        self.assertIn("core.hooksPath=/dev/null", clone[clone.index("-c") + 1])

    def test_a_folder_is_copied_in_and_no_network_is_possible_for_it(self):
        steps = sb.commands("podman", "folder", SANDBOX_HOME, "n", network=False)
        self.assertEqual(steps[0][1][steps[0][1].index("--network") + 1], "none")
        self.assertEqual(steps[1][1][:2], ["podman", "cp"])
        self.assertIn("chown", steps[2][1], "the copy is made writable for the container")
        self.assertEqual(steps[0][1].count("--cap-add"), 1)
        self.assertEqual(steps[-1][1][:3], ["podman", "rm", "-f"], "the container is always deleted last")

    def test_image_names_are_validated_and_dry_run_shows_everything(self):
        with self.assertRaises(ValueError):
            sb.commands("docker", "github", "a/b", "n", image="x --privileged")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(sb.open_sandbox("owner/name", dry_run=True), 0)
        self.assertIn("docker rm -f", out.getvalue())
        with self.assertRaises(ValueError):
            sb.open_sandbox("owner/name", network=False, dry_run=True)


class Credentials(unittest.TestCase):
    def home(self, files):
        home = tempfile.mkdtemp(prefix="creds-")
        for rel, text in files.items():
            path = os.path.join(home, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(text)
        return home

    def test_an_empty_home_has_nothing(self):
        self.assertEqual(ca.audit(self.home({}))["items"], [])

    def test_aws_keys_are_found_and_the_secret_is_never_in_the_result(self):
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        home = self.home({".aws/credentials": f"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = {secret}\n"})
        res = ca.audit(home)
        self.assertEqual([i["id"] for i in res["items"]], ["aws"])
        blob = json.dumps(res)
        self.assertNotIn(secret, blob)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", blob, "only the last 4 characters of the key ID are shown")
        self.assertIn("ending MPLE", blob)
        self.assertIn("aws configure sso", blob)

    def test_aws_with_sso_set_up_tells_you_the_keys_can_go(self):
        home = self.home({".aws/credentials": "[old]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = x\n",
                          ".aws/config": "[sso-session s]\nsso_start_url = https://x.awsapps.com/start\n"})
        item = ca.audit(home)["items"][0]
        self.assertIn("SSO is already set up", item["summary"])
        self.assertFalse(any("configure sso" in s for s in item["steps"]))

    def test_each_kind_is_recognised_and_safe_setups_are_not(self):
        home = self.home({
            ".npmrc": "//registry.npmjs.org/:_authToken=npm_abcdef\n",
            ".docker/config.json": json.dumps({"auths": {"ghcr.io": {"auth": "dTpw"}}}),
            ".git-credentials": "https://user:tok@github.com\n",
            ".netrc": "machine example.com login a password b\n",
            ".pypirc": "[pypi]\nusername = __token__\npassword = pypi-AgEI\n",
        })
        self.assertEqual(sorted(i["id"] for i in ca.audit(home)["items"]), ["docker", "git-credentials", "netrc", "npm", "pypi"])
        safe = self.home({".npmrc": "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n# _authToken=old\n",
                          ".docker/config.json": json.dumps({"credsStore": "osxkeychain", "auths": {"ghcr.io": {}}}),
                          ".aws/credentials": "[default]\n; nothing\n"})
        self.assertEqual(ca.audit(safe)["items"], [])

    def test_old_files_are_marked_old(self):
        home = self.home({".npmrc": "//registry.npmjs.org/:_authToken=npm_abcdef\n"})
        path = os.path.join(home, ".npmrc")
        old = time.time() - 200 * 86400
        os.utime(path, (old, old))
        item = ca.audit(home)["items"][0]
        self.assertTrue(item["old"])
        self.assertGreaterEqual(item["age_days"], 199)

    def test_a_broken_file_does_not_hide_the_others(self):
        home = self.home({".docker/config.json": "{ not json", ".npmrc": "//r/:_authToken=abc123\n"})
        self.assertEqual([i["id"] for i in ca.audit(home)["items"]], ["npm"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
