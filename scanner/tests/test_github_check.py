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
