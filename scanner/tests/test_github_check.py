"""Offline tests for github_check.py (no network).  Run:  python3 scanner/tests/test_github_check.py"""
import datetime
import importlib.util
import io
import os
import shutil
import tarfile
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("github_check", os.path.join(HERE, "..", "github_check.py"))
gc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gc)


def tarball(entries):
    """entries: [(name, bytes | None for a symlink to /etc/passwd)]"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class SafeExtract(unittest.TestCase):
    def setUp(self):
        self.dest = tempfile.mkdtemp(prefix="ghcheck-")
        self.outside = os.path.join(os.path.dirname(self.dest), "escaped-by-test.txt")

    def tearDown(self):
        shutil.rmtree(self.dest, ignore_errors=True)
        if os.path.exists(self.outside):
            os.remove(self.outside)

    def test_regular_files_extracted_without_top_folder(self):
        gc.safe_extract(tarball([("owner-repo-abc/package.json", b"{}"), ("owner-repo-abc/src/a.js", b"x")]), self.dest)
        self.assertTrue(os.path.isfile(os.path.join(self.dest, "package.json")))
        self.assertTrue(os.path.isfile(os.path.join(self.dest, "src", "a.js")))

    def test_path_traversal_absolute_paths_and_links_are_skipped(self):
        gc.safe_extract(tarball([("top/../../escaped-by-test.txt", b"x"), ("/abs.txt", b"x"),
                                 ("top/link", None), ("top/ok.txt", b"ok")]), self.dest)
        self.assertFalse(os.path.exists(self.outside))
        self.assertEqual(sorted(os.listdir(self.dest)), ["ok.txt"])


class Bursts(unittest.TestCase):
    def test_counts_pushes_within_one_hour(self):
        t0 = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        times = [t0 + datetime.timedelta(minutes=m) for m in (0, 5, 10, 50, 59, 200, 500)]
        n, start = gc.bursts(times)
        self.assertEqual((n, start), (5, t0))
        self.assertEqual(gc.bursts([])[0], 0)


class WormRepos(unittest.TestCase):
    """Repositories the worms create in the victim's own account to publish what they stole."""

    def test_exfiltration_repos_are_found_by_description_or_name(self):
        repos = [{"full_name": "me/x8k2ab91mn0qz7c4rt", "name": "x8k2ab91mn0qz7c4rt", "description": "Sha1-Hulud: The Second Coming."},
                 {"full_name": "me/Shai-Hulud", "name": "Shai-Hulud", "description": None},
                 {"full_name": "me/s1ngularity-repository-0", "name": "s1ngularity-repository-0", "description": ""},
                 {"full_name": "me/r", "name": "r", "description": "Shai-Hulud: Here We Go Again."},
                 {"full_name": "me/dune-notes", "name": "dune-notes", "description": "My notes about Shai-Hulud in Dune"},
                 {"full_name": "me/app", "name": "app", "description": "a web app"}]
        self.assertEqual([full for full, _ in gc.worm_repos(repos)],
                         ["me/x8k2ab91mn0qz7c4rt", "me/Shai-Hulud", "me/s1ngularity-repository-0", "me/r"])

    def test_account_check_reports_them_as_danger(self):
        class FakeClient:
            truncated = []

            def get_all(self, path):
                return [{"full_name": "me/x8k2ab91mn0qz7c4rt", "name": "x8k2ab91mn0qz7c4rt", "pushed_at": "2020-01-01T00:00:00Z",
                         "description": "Sha1-Hulud: The Second Coming."}]
        result = {"findings": [], "notes": []}
        gc.check_account(FakeClient(), None, "me", "me", 7, 5, False, False, result, {})
        self.assertEqual([(f[0], f[1]) for f in result["findings"]], [("DANGER", "me/x8k2ab91mn0qz7c4rt")])
        self.assertIn("rotate", result["findings"][0][2])


class AccountAudit(unittest.TestCase):
    """Ways an attacker keeps access after stealing a token, on the repositories you administer."""

    def setUp(self):
        self.audit_file = gc.AUDIT_FILE
        gc.AUDIT_FILE = os.path.join(tempfile.mkdtemp(), "audit.json")

    def tearDown(self):
        gc.AUDIT_FILE = self.audit_file

    def client(self, answers):
        class FakeClient:
            gh = "gh"
            truncated = []

            def get(self, path, limit=0):
                if path not in answers:
                    raise RuntimeError("HTTP 404: Not Found")
                return answers[path]
        return FakeClient()

    def test_runners_keys_hooks_invitations_and_force_push(self):
        now = datetime.datetime(2026, 11, 19, tzinfo=datetime.timezone.utc)
        repos = [{"full_name": "me/app", "default_branch": "main", "permissions": {"admin": True}},
                 {"full_name": "me/safe", "default_branch": "main", "permissions": {"admin": True}},
                 {"full_name": "other/lib", "default_branch": "main", "permissions": {"admin": False}}]
        answers = {
            "/repos/me/app/actions/runners": {"runners": [{"name": "SHA1HULUD", "os": "macOS", "status": "online"}]},
            "/repos/me/app/keys": [{"title": "deploy", "created_at": "2026-11-10T00:00:00Z", "read_only": False},
                                   {"title": "old ci", "created_at": "2024-01-01T00:00:00Z", "read_only": True}],
            "/repos/me/app/hooks": [{"config": {"url": "https://webhook.site/abc"}, "created_at": "2024-01-01T00:00:00Z"}],
            "/repos/me/app/invitations": [{"invitee": {"login": "stranger"}, "permissions": "write"}],
            "/repos/me/app/rules/branches/main": [],
            "/repos/me/safe/actions/runners": {"runners": []}, "/repos/me/safe/keys": [], "/repos/me/safe/hooks": [],
            "/repos/me/safe/invitations": [], "/repos/me/safe/rules/branches/main": [{"type": "non_fast_forward"}],
            "/user/keys": [{"title": "new laptop", "created_at": "2026-11-18T00:00:00Z"}],
        }
        result = {"findings": [], "notes": []}
        gc.audit_account(self.client(answers), repos, result, now=now)
        text = "\n".join(f"{f[0]} {f[1]} {f[2]}" for f in result["findings"])
        self.assertIn("DANGER me/app self-hosted runner 'SHA1HULUD'", text)
        self.assertIn("deploy key 'deploy'", text)
        self.assertNotIn("old ci", text, "old keys are not news")
        self.assertIn("webhook.site", text)
        self.assertIn("stranger", text)
        self.assertIn("SSH key 'new laptop'", text)
        self.assertNotIn("other/lib", text, "only repositories you administer")
        self.assertTrue(any("1 of 2 repositories" in n and "me/app" in n for n in result["notes"]), result["notes"])

    def test_a_missing_scope_is_not_an_error_and_results_are_cached_for_a_day(self):
        repos = [{"full_name": "me/app", "default_branch": "main", "permissions": {"admin": True}}]
        result = {"findings": [], "notes": []}
        gc.audit_account(self.client({}), repos, result)                         # every call: 404
        self.assertEqual(result["findings"], [])
        calls = []

        class Counting:
            gh, truncated = "gh", []

            def get(self, path, limit=0):
                calls.append(path)
                raise RuntimeError("HTTP 404")
        gc.audit_account(Counting(), repos, {"findings": [], "notes": []})
        self.assertEqual(calls, [], "a recent audit is reused")


class Usernames(unittest.TestCase):
    def test_invalid_usernames_are_refused_before_any_request(self):
        self.assertEqual(gc.main(["bad/name"]), 3)
        self.assertEqual(gc.main(["a" * 40]), 3)


class Paging(unittest.TestCase):
    def test_reads_every_page_not_just_the_first_100(self):
        pages = {1: list(range(100)), 2: list(range(100, 200)), 3: list(range(200, 231))}
        client = gc.Client(use_gh=False)
        seen = []

        def fake_get(path, limit=0):
            seen.append(path)
            return pages[int(path.rsplit("page=", 1)[1])]
        client.get = fake_get
        self.assertEqual(len(client.get_all("/user/repos?sort=pushed")), 231)
        self.assertEqual(len(seen), 3)
        self.assertIn("/user/repos?sort=pushed&per_page=100&page=1", seen)


class SizeLimits(unittest.TestCase):
    def setUp(self):
        self.dest = tempfile.mkdtemp(prefix="ghcheck-")
        self.saved = gc.MAX_EXTRACTED, gc.MAX_FILE, gc.KEEP_FREE

    def tearDown(self):
        gc.MAX_EXTRACTED, gc.MAX_FILE, gc.KEEP_FREE = self.saved
        shutil.rmtree(self.dest, ignore_errors=True)

    def test_oversized_files_are_skipped_and_counted(self):
        gc.MAX_FILE = 10
        counts = gc.safe_extract(tarball([("top/big.bin", b"x" * 11), ("top/small.js", b"ok")]), self.dest)
        self.assertEqual(counts["too_large"], 1)
        self.assertEqual(os.listdir(self.dest), ["small.js"])

    def test_extraction_stops_before_the_cap(self):
        gc.MAX_EXTRACTED = 25
        with self.assertRaises(RuntimeError):
            gc.safe_extract(tarball([("top/a", b"x" * 10), ("top/b", b"x" * 10), ("top/c", b"x" * 10)]), self.dest)

    def test_refuses_when_the_disk_is_nearly_full(self):
        gc.KEEP_FREE = shutil.disk_usage(self.dest).free + gc.GB
        with self.assertRaises(RuntimeError):
            gc.safe_extract(tarball([("top/a", b"x")]), self.dest)

    def test_archive_from_a_file_path(self):
        path = os.path.join(self.dest, "a.tar.gz")
        with open(path, "wb") as f:
            f.write(tarball([("top/src/a.js", b"x")]))
        out = os.path.join(self.dest, "files")
        os.makedirs(out)
        self.assertEqual(gc.safe_extract(path, out), {"too_large": 0, "unwritable": 0, "same_name": 0})
        self.assertTrue(os.path.isfile(os.path.join(out, "src", "a.js")))


class EdgeCases(unittest.TestCase):
    def setUp(self):
        self.dest = tempfile.mkdtemp(prefix="ghcheck-")

    def tearDown(self):
        shutil.rmtree(self.dest, ignore_errors=True)

    def files(self):
        return sorted(os.path.relpath(os.path.join(d, f), self.dest) for d, _, fs in os.walk(self.dest) for f in fs)

    def test_names_differing_only_in_case_are_both_kept(self):
        counts = gc.safe_extract(tarball([("top/.vscode/Tasks.json", b"harmless"),
                                          ("top/.vscode/tasks.json", b"malware")]), self.dest)
        self.assertEqual(counts["same_name"], 1)
        contents = sorted(open(os.path.join(self.dest, f), "rb").read() for f in self.files())
        self.assertEqual(contents, [b"harmless", b"malware"])

    def test_unicode_forms_of_the_same_name_are_both_kept(self):
        counts = gc.safe_extract(tarball([("top/caf\u00e9.js", b"a"), ("top/cafe\u0301.js", b"b")]), self.dest)
        self.assertEqual(counts["same_name"], 1)
        self.assertEqual(len(self.files()), 2)

    def test_one_unwritable_file_does_not_stop_the_others(self):
        # a file and a folder with the same name: the second can't be created, the rest still are
        counts = gc.safe_extract(tarball([("top/a", b"file"), ("top/a/b.js", b"x"), ("top/c.js", b"ok")]), self.dest)
        self.assertEqual(counts["unwritable"], 1)
        self.assertIn("c.js", self.files())

    def test_dot_and_empty_path_parts_are_ignored(self):
        gc.safe_extract(tarball([("top/./src//a.js", b"x")]), self.dest)
        self.assertEqual(self.files(), [os.path.join("src", "a.js")])

    def test_seen_cache_respects_the_scan_mode(self):
        repo = {"full_name": "o/r", "pushed_at": "2026-01-01T00:00:00Z"}
        self.assertTrue(gc.seen_ok({"o/r": "2026-01-01T00:00:00Z"}, repo, False))
        self.assertFalse(gc.seen_ok({"o/r": "2026-01-01T00:00:00Z"}, repo, True))      # default-only isn't enough
        self.assertTrue(gc.seen_ok({"o/r": "2026-01-01T00:00:00Z|all"}, repo, False))
        self.assertFalse(gc.seen_ok({"o/r": "2025-12-31T00:00:00Z|all"}, repo, True))  # pushed since

    def test_bad_numbers_are_refused(self):
        for args in (["--days", "x"], ["--days"], ["--max-repos", "0"], ["--days", "-3"]):
            self.assertEqual(gc.main(["someone"] + args), 3, args)

    def test_stale_temp_folders_are_removed(self):
        old = tempfile.mkdtemp(prefix=gc.TMP_PREFIX)
        fresh = tempfile.mkdtemp(prefix=gc.TMP_PREFIX)
        os.utime(old, (time.time() - 3 * 86400,) * 2)
        gc.remove_stale_temp()
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(fresh))
        shutil.rmtree(fresh)

    def test_paging_stops_at_the_cap_and_says_so(self):
        client = gc.Client(use_gh=False)
        client.get = lambda path, limit=0: list(range(gc.PER_PAGE))   # never ends
        self.assertEqual(len(client.get_all("/x")), gc.MAX_PAGES * gc.PER_PAGE)
        self.assertEqual(client.truncated, ["/x"])

    def test_rate_limit_is_its_own_error(self):
        with self.assertRaises(gc.RateLimited):
            gc.gh_error("gh: API rate limit exceeded for user", 1)
        with self.assertRaises(RuntimeError):
            gc.gh_error("", 1)


class Repositories(unittest.TestCase):
    """Repositories named one by one (Settings > GitHub > Repositories to scan, or --repo)."""

    def test_names_urls_and_ssh_addresses(self):
        for text in ("octo/hello", " octo/hello ", "https://github.com/octo/hello", "https://github.com/octo/hello.git",
                     "http://www.github.com/octo/hello/", "https://github.com/octo/hello/tree/main/src",
                     "https://github.com/octo/hello?tab=readme#top", "git@github.com:octo/hello.git",
                     "ssh://git@github.com/octo/hello"):
            self.assertEqual(gc.parse_repo(text), "octo/hello", text)
        self.assertEqual(gc.parse_repo("Inroad-Ai/inroad-api"), "Inroad-Ai/inroad-api")
        self.assertEqual(gc.parse_repo("a/my.repo_name-2"), "a/my.repo_name-2")

    def test_anything_else_is_refused(self):
        for text in ("", "octo", "octo/", "/hello", "octo/hello/extra", "https://gitlab.com/octo/hello", "octo/hello world",
                     "-octo/hello", "octo/..", "octo/.", "../../etc/passwd", "octo/hello;rm -rf ~", "a" * 40 + "/x"):
            with self.assertRaises(ValueError, msg=text):
                gc.parse_repo(text)

    def test_arguments(self):
        o = gc.parse_args(["--repo", "octo/hello", "--repo", "https://github.com/OCTO/hello", "--repo", "a/b", "--json"])
        self.assertEqual((o["user"], o["repos"], "--json" in o["flags"]), ("", ["octo/hello", "a/b"], True))
        o = gc.parse_args(["@me", "--days", "30", "--repo", "a/b"])
        self.assertEqual((o["user"], o["days"], o["repos"]), ("me", 30, ["a/b"]))
        for bad in ([], ["--json"], ["--repo"], ["--repo", "nope"], ["me", "--days", "0"], ["bad/name"]):
            with self.assertRaises(ValueError, msg=bad):
                gc.parse_args(bad)
        self.assertEqual(gc.main(["--repo", "not a repo"]), 3)

    def test_listed_repositories_are_scanned_on_every_branch(self):
        repos = {"octo/clean": {"full_name": "octo/clean", "pushed_at": "2026-01-02T00:00:00Z", "size": 10, "default_branch": "main",
                                "owner": {"login": "octo", "type": "User"}, "permissions": {"admin": False, "push": True}},
                 "Octo/Old": {"full_name": "Octo/Old", "pushed_at": "2026-01-01T00:00:00Z", "size": 10, "default_branch": "main"}}
        branches = {"octo/clean": [{"name": "main"}, {"name": "dev"}], "Octo/Old": [{"name": "main"}]}

        class FakeClient:
            truncated = []

            def get(self, path, limit=0):
                name = path[len("/repos/"):]
                if name.lower() == "octo/old":
                    return repos["Octo/Old"]
                if name not in repos:
                    raise RuntimeError("gh: Not Found (HTTP 404)")
                return repos[name]

            def get_all(self, path):
                return branches[path.split("/repos/")[1].rsplit("/branches", 1)[0]]

        scanned = []
        original = gc.scan_branch
        gc.scan_branch = lambda client, cr, repo, branch, result, maybe_empty=False, shared=False: \
            scanned.append((repo, branch, shared)) or "clean"
        try:
            result = {"scanned": ["someone/else"], "branches_scanned": 0, "findings": [], "notes": [], "listed": []}
            seen = {"Octo/Old": "2026-01-01T00:00:00Z|all"}                    # clean on every branch since its last push
            gc.check_listed(FakeClient(), None, ["octo/clean", "octo/old", "octo/missing", "someone/else"], False, result, seen)
        finally:
            gc.scan_branch = original
        self.assertEqual(scanned, [("octo/clean", "main", True), ("octo/clean", "dev", True)])   # someone else's: said so
        self.assertEqual([(r["repo"], r["outcome"], r["branches"]) for r in result["listed"]],
                         [("octo/clean", "clean", 2), ("Octo/Old", "unchanged", 0), ("octo/missing", "error", 0),
                          ("someone/else", "scanned above", 0)])
        self.assertEqual(result["findings"], [["WARNING", "octo/missing", "not scanned: not found, or your GitHub login can't see it"]])
        self.assertEqual(seen["octo/clean"], "2026-01-02T00:00:00Z|all")


class Scope(unittest.TestCase):
    """Settings > GitHub: every repository you can push to, or only yours and your organizations'."""

    def test_listing_follows_the_scope(self):
        self.assertIn("affiliation=owner,organization_member,collaborator", gc.account_path("me", "me"))
        self.assertIn("affiliation=owner,organization_member&", gc.account_path("me", "Me", owned_only=True))
        self.assertEqual(gc.account_path("you", "me"), "/users/you/repos?type=owner&sort=full_name")

    def test_repositories_to_choose_from_are_grouped(self):
        rows = [{"full_name": "me/a", "owner": {"login": "me", "type": "User"}, "pushed_at": "2026-01-01T00:00:00Z"},
                {"full_name": "Org/b", "owner": {"login": "Org", "type": "Organization"}, "private": True, "pushed_at": "2026-03-01T00:00:00Z"},
                {"full_name": "pal/c", "owner": {"login": "pal", "type": "User"}, "pushed_at": "2026-02-01T00:00:00Z"},
                "garbage"]

        class FakeClient:
            def __init__(self, use_gh):
                pass

            def get_all(self, path):
                return rows
        login, client = gc.gh_login, gc.Client
        gc.gh_login, gc.Client = (lambda: "me"), FakeClient
        try:
            got = gc.list_repos()
        finally:
            gc.gh_login, gc.Client = login, client
        self.assertEqual([(r["repo"], r["kind"], r["private"]) for r in got],
                         [("Org/b", "org", True), ("pal/c", "shared", False), ("me/a", "yours", False)])   # newest push first


@unittest.skipIf(os.name == "nt", "uses a POSIX shell script as a stand-in for gh")
class Download(unittest.TestCase):
    """download() through a fake `gh` that writes a given number of bytes, then exits with a given code."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ghcheck-")
        self.saved = gc.MAX_ARCHIVE, gc.DOWNLOAD_TIMEOUT
        self.client = gc.Client(use_gh=False)
        self.dest = os.path.join(self.dir, "archive.tar.gz")

    def tearDown(self):
        gc.MAX_ARCHIVE, gc.DOWNLOAD_TIMEOUT = self.saved
        shutil.rmtree(self.dir, ignore_errors=True)

    def fake_gh(self, script):
        path = os.path.join(self.dir, "gh")
        with open(path, "w") as f:
            f.write("#!/bin/sh\n" + script + "\n")
        os.chmod(path, 0o755)
        self.client.gh = path

    def test_streams_to_disk(self):
        self.fake_gh("head -c 3000000 /dev/zero")
        self.assertEqual(self.client.download("/x", self.dest), 3000000)
        self.assertEqual(os.path.getsize(self.dest), 3000000)

    def test_stops_and_kills_gh_when_too_big(self):
        gc.MAX_ARCHIVE = 2 * 1024 * 1024
        self.fake_gh("cat /dev/zero")                      # would never end on its own
        with self.assertRaises(RuntimeError) as e:
            self.client.download("/x", self.dest)
        self.assertIn("larger than", str(e.exception))

    def test_gh_error_is_reported_even_without_a_message(self):
        self.fake_gh("exit 4")
        with self.assertRaises(RuntimeError) as e:
            self.client.download("/x", self.dest)
        self.assertIn("exit code 4", str(e.exception))

    def test_gh_error_message_is_passed_on(self):
        self.fake_gh("echo 'HTTP 404: Not Found' >&2; exit 1")
        with self.assertRaises(RuntimeError) as e:
            self.client.download("/x", self.dest)
        self.assertIn("404", str(e.exception))

    def test_a_stalled_download_is_stopped(self):
        gc.DOWNLOAD_TIMEOUT = 1
        self.fake_gh("exec sleep 30")
        with self.assertRaises(RuntimeError) as e:
            self.client.download("/x", self.dest)
        self.assertIn("longer than", str(e.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
