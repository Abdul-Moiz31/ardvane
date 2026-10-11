"""Tests for the signed detection feed (feed.py, ed25519.py) and how the scanner uses it. Offline: feeds are signed
here with a throwaway test key and served from a temporary folder.  Run:  python3 scanner/tests/test_feed.py"""
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(HERE, "..")
sys.path.insert(0, SCANNER)
import ed25519      # noqa: E402
import feed         # noqa: E402

# RFC 8032 section 7.1, TEST 1 and TEST 2: (secret key, public key, message, signature)
RFC = [("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
       ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")]
TEST_SECRET = bytes.fromhex("11" * 32)


def _compress(point):
    x, y, z, _ = point
    zinv = pow(z, ed25519.P - 2, ed25519.P)
    x, y = x * zinv % ed25519.P, y * zinv % ed25519.P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def sign(secret, message):
    """RFC 8032 signing - test-only: Ardvane itself never signs, it only verifies. Returns (public key, signature)."""
    h = hashlib.sha512(secret).digest()
    a = (int.from_bytes(h[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
    public = _compress(ed25519._mul(a, ed25519.BASE))
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % ed25519.Q
    big_r = _compress(ed25519._mul(r, ed25519.BASE))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little") % ed25519.Q
    return public, big_r + ((r + k * a) % ed25519.Q).to_bytes(32, "little")


TEST_PUBLIC = sign(TEST_SECRET, b"")[0]


def signed(data, secret=TEST_SECRET):
    body = json.dumps(data).encode()
    return sign(secret, body)[1] + body


def good(sequence=5, **lists):
    data = {"schema": 1, "sequence": sequence, "published": "2026-10-12"}
    data.update(lists)
    return data


class Signatures(unittest.TestCase):
    def test_rfc_8032_vectors(self):
        for secret, public, msg, sig in RFC:
            self.assertEqual(sign(bytes.fromhex(secret), bytes.fromhex(msg)), (bytes.fromhex(public), bytes.fromhex(sig)))
            self.assertTrue(ed25519.verify(bytes.fromhex(public), bytes.fromhex(msg), bytes.fromhex(sig)))

    def test_anything_changed_is_rejected(self):
        public, sig = bytes.fromhex(RFC[1][1]), bytes.fromhex(RFC[1][3])
        for i in (0, 31, 32, 63):
            bad = bytearray(sig)
            bad[i] ^= 1
            self.assertFalse(ed25519.verify(public, b"\x72", bytes(bad)))
        self.assertFalse(ed25519.verify(public, b"\x73", sig))
        self.assertFalse(ed25519.verify(bytes.fromhex(RFC[0][1]), b"\x72", sig))
        self.assertFalse(ed25519.verify(public, b"\x72", sig[:63]))
        # s >= group order: a malleable variant of a valid signature
        s = int.from_bytes(sig[32:], "little") + ed25519.Q
        self.assertFalse(ed25519.verify(public, b"\x72", sig[:32] + s.to_bytes(32, "little")))


class Feed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ardvane-feed-")
        self.saved = feed.PUBLIC_KEY, feed.CACHE
        feed.PUBLIC_KEY, feed.CACHE = TEST_PUBLIC, os.path.join(self.tmp, "cache", "indicators.signed")

    def tearDown(self):
        feed.PUBLIC_KEY, feed.CACHE = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def serve(self, blob):
        path = os.path.join(self.tmp, "served.signed")
        with open(path, "wb") as f:
            f.write(blob)
        return "file://" + path

    def test_a_valid_feed_is_accepted(self):
        f = feed.parse(signed(good(hashes=["a" * 64], hosts=["evil-c2.example.net"], ips=["185.220.101.250"],
                                   markers=["xor-key-1234"], npm=["@evil/pkg", "bad-pkg"], pypi=["bad-py"])))
        self.assertEqual((f["sequence"], f["npm"], f["hosts"]), (5, ["@evil/pkg", "bad-pkg"], ["evil-c2.example.net"]))

    def test_signature_and_key(self):
        blob = signed(good(npm=["bad-pkg"]))
        with self.assertRaises(feed.FeedError):
            feed.parse(blob[:64] + blob[64:].replace(b"bad-pkg", b"bad-pkh"))          # content changed after signing
        with self.assertRaises(feed.FeedError):
            feed.parse(signed(good(), secret=bytes.fromhex("22" * 32)))               # signed with another key
        with self.assertRaises(feed.FeedError):
            feed.parse(b"x" * 10)

    def test_strict_content_checks(self):
        for lists in ({"hashes": ["XYZ"]}, {"hosts": ["github.com"]}, {"hosts": ["not a host"]}, {"ips": ["10.0.0.1"]},
                      {"ips": ["127.0.0.1"]}, {"ips": ["::1"]}, {"markers": ["short"]}, {"npm": ["Bad Name"]},
                      {"pypi": ["../x"]}, {"npm": "bad-pkg"}, {"npm": [7]}):
            with self.assertRaises(feed.FeedError, msg=str(lists)):
                feed.parse(signed(good(**lists)))
        for data in ({"schema": 2, "sequence": 1}, {"schema": 1}, {"schema": 1, "sequence": True}, [1, 2]):
            with self.assertRaises(feed.FeedError, msg=str(data)):
                feed.parse(signed(data))
        saved = dict(feed.LIMITS)
        feed.LIMITS["npm"] = 2
        try:
            with self.assertRaises(feed.FeedError):
                feed.parse(signed(good(npm=["a", "b", "c"])))
        finally:
            feed.LIMITS.clear()
            feed.LIMITS.update(saved)

    def test_update_stores_newer_feeds_and_refuses_older_ones(self):
        self.assertIsNone(feed.cached())
        self.assertEqual(feed.update(self.serve(signed(good(5, npm=["bad-pkg"]))))[0], "updated")
        self.assertEqual(feed.cached()["npm"], ["bad-pkg"])
        self.assertEqual(feed.update(self.serve(signed(good(5, npm=["bad-pkg"]))))[0], "current")
        with self.assertRaises(feed.FeedError):                                        # replaying an old signed feed
            feed.update(self.serve(signed(good(4, npm=[]))))
        self.assertEqual(feed.update(self.serve(signed(good(6, npm=["bad-pkg", "worse"]))))[0], "updated")
        self.assertEqual(feed.cached()["sequence"], 6)

    def test_a_bad_download_keeps_the_last_good_copy(self):
        feed.update(self.serve(signed(good(5, npm=["bad-pkg"]))))
        for blob in (signed(good(9), secret=bytes.fromhex("22" * 32)), b"<html>error page</html>" * 10):
            with self.assertRaises(feed.FeedError):
                feed.update(self.serve(blob))
        with self.assertRaises(feed.FeedError):
            feed.update("file://" + os.path.join(self.tmp, "missing"))
        self.assertEqual(feed.cached()["sequence"], 5)

    def test_a_changed_cache_file_is_not_used(self):
        feed.update(self.serve(signed(good(5, npm=["bad-pkg"]))))
        with open(feed.CACHE, "rb") as f:
            blob = f.read()
        with open(feed.CACHE, "wb") as f:
            f.write(blob.replace(b"bad-pkg", b"bad-pkh"))
        self.assertIsNone(feed.cached())
        self.assertEqual(feed.indicators()["npm"], [])


class ScannerUsesTheFeed(unittest.TestCase):
    """checkrepo adds the feed's indicators to its built-in ones."""

    def load_scanner(self, indicators):
        fake = types.ModuleType("feed")
        fake.cached = lambda: indicators
        saved_env, saved_mod = os.environ.pop("ARDVANE_NO_FEED", None), sys.modules.get("feed")
        sys.modules["feed"] = fake
        try:
            spec = importlib.util.spec_from_file_location("checkrepo_with_feed", os.path.join(SCANNER, "checkrepo.py"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
        finally:
            if saved_mod is not None:
                sys.modules["feed"] = saved_mod
            if saved_env is not None:
                os.environ["ARDVANE_NO_FEED"] = saved_env

    def test_feed_indicators_are_detected(self):
        cr = self.load_scanner(dict(feed.empty(), sequence=3, published="x", hosts=["evil-c2.example.net"],
                                    ips=["185.220.101.250"], markers=["xor-key-1234"], npm=["bad-pkg"], hashes=["b" * 64]))
        self.assertTrue(cr.marker_hits("fetch('https://api.evil-c2.example.net/x')"))      # subdomains count too
        self.assertFalse(cr.marker_hits("fetch('https://notevil-c2.example.net/x')"))
        self.assertTrue(cr.marker_hits("connect('185.220.101.250', 443)"))
        self.assertFalse(cr.marker_hits("version 1.185.220.101.250"))
        self.assertTrue(cr.marker_hits("const k = 'xor-key-1234';"))
        self.assertEqual(cr.npm_names_in('"node_modules/bad-pkg": {}, "node_modules/@acme/bad-pkg": {}'), {"bad-pkg"})
        self.assertIn("b" * 64, cr.KNOWN_HASHES)
        self.assertTrue(cr.marker_hits("global['" + "!']='1-2';"))                         # built-ins still there

    def test_without_a_feed_only_built_ins(self):
        cr = self.load_scanner(None)
        self.assertIsNone(cr.FEED)
        self.assertFalse(cr.marker_hits("https://api.evil-c2.example.net"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
