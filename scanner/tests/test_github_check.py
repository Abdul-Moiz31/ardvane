"""Offline tests for github_check.py (no network).  Run:  python3 scanner/tests/test_github_check.py"""
import datetime
import importlib.util
import io
import os
import shutil
import tarfile
import tempfile
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
