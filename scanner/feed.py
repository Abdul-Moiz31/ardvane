#!/usr/bin/env python3
"""feed — Ardvane's detection feed: new malware fingerprints between releases, signed.

Part of Ardvane (MIT License). Python 3.8+, no dependencies.

  feed.py update [--quiet]   download the latest feed, if it is newer and correctly signed
  feed.py show               what the feed on this computer holds

Attackers change their code to slip past detections, and many people update their tools rarely. The feed lets the
scanner learn new fingerprints (payload hashes, attacker hosts and IPs, code markers, malicious packages) every day,
without an upgrade.

Trust - the feed is a single file: a 64-byte Ed25519 signature followed by the JSON it signs. It is used only if:
  - the signature matches PUBLIC_KEY. The private half lives in a GitHub secret that only Ardvane's feed workflow,
    running on main, can use, so a stolen GitHub token can't publish a feed;
  - every entry passes strict checks (format, size, no overly common domains or private IPs);
  - its sequence number is higher than the copy already here, so an old signed feed can't be replayed.
The feed can only ADD indicators to those built into the scanner - it never removes one, and it never names files
for Ardvane to move or change. A failed download or a bad signature leaves the last good copy in place.

Privacy: updating downloads one file from GitHub. Nothing about this computer is sent.
Exit code: 0 updated or already current, 1 the update failed (the last good copy is still used), 3 usage error.
"""
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ed25519 import verify                                    # noqa: E402
from kitlib import DEST, safe_output, write_atomic            # noqa: E402

FEED_URL = "https://github.com/Abdul-Moiz31/ardvane/releases/download/feed/indicators.signed"
PUBLIC_KEY = bytes.fromhex("36049bba64826ff63cb3f6940af7d2f7fd3e01388b95f1bb2d1c3d96e9e2afdc")
CACHE = os.path.join(DEST, "indicators.signed")
SCHEMA = 1
MAX_BYTES = 8 * 1024 * 1024
TIMEOUT = 30

# Per-list limits, and what a valid entry looks like. Markers are matched as plain substrings in every file, so there
# are few of them; everything else is looked up in a set, so those lists can be large without slowing a scan.
LIMITS = {"hashes": 50000, "hosts": 20000, "ips": 20000, "markers": 100, "npm": 300000, "pypi": 100000}
HASH_RE = re.compile(r"[0-9a-f]{64}")
HOST_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}")
NPM_RE = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*")
PYPI_RE = re.compile(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?")
# Domains that real projects mention all the time: a feed entry for one of them would flag everything.
COMMON_HOSTS = {"github.com", "githubusercontent.com", "raw.githubusercontent.com", "github.io", "npmjs.com", "npmjs.org",
                "registry.npmjs.org", "pypi.org", "pythonhosted.org", "google.com", "googleapis.com", "gstatic.com",
                "microsoft.com", "apple.com", "amazonaws.com", "cloudflare.com", "vercel.app", "vercel.com",
                "netlify.app", "onrender.com", "herokuapp.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
                "example.com", "localhost.localdomain"}


class FeedError(Exception):
    """The feed can't be used (bad signature, bad content, older than the copy here, or no connection)."""


def empty():
    return {key: [] for key in LIMITS}


def _check_entry(key, v):
    if not isinstance(v, str):
        return False
    if key == "hashes":
        return bool(HASH_RE.fullmatch(v))
    if key == "hosts":
        return len(v) <= 253 and bool(HOST_RE.fullmatch(v)) and v not in COMMON_HOSTS
    if key == "ips":
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return False
        return ip.version == 4 and ip.is_global
    if key == "markers":
        return 8 <= len(v) <= 200 and v.isprintable()
    if key == "npm":
        return len(v) <= 214 and bool(NPM_RE.fullmatch(v))
    return len(v) <= 100 and bool(PYPI_RE.fullmatch(v))     # pypi (names are compared lower-case)


def parse(blob):
    """The verified, validated feed from a signed file's bytes, or raise FeedError."""
    if not isinstance(blob, bytes) or not 64 < len(blob) <= MAX_BYTES:
        raise FeedError("not a feed file")
    signature, body = blob[:64], blob[64:]
    if not verify(PUBLIC_KEY, body, signature):
        raise FeedError("the signature doesn't match Ardvane's feed key")
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise FeedError("the feed is not valid JSON")
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise FeedError("unsupported feed format (update Ardvane)")
    seq = data.get("sequence")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
        raise FeedError("the feed has no sequence number")
    feed = {"sequence": seq, "published": str(data.get("published", ""))[:40]}
    for key, limit in LIMITS.items():
        values = data.get(key, [])
        if not isinstance(values, list) or len(values) > limit:
            raise FeedError(f"'{key}' must be a list of at most {limit} entries")
        bad = next((v for v in values if not _check_entry(key, v)), None)
        if bad is not None:
            raise FeedError(f"invalid '{key}' entry: {str(bad)[:60]!r}")
        feed[key] = sorted(set(values))
    return feed


def cached():
    """The feed on this computer (checked again: the file could have been changed), or None."""
    try:
        with open(CACHE, "rb") as f:
            return parse(f.read(MAX_BYTES + 1))
    except (OSError, FeedError):
        return None


def indicators():
    """The indicator lists the scanner adds to its built-in ones (all empty without a valid feed)."""
    return cached() or empty()


def download(url=FEED_URL, timeout=TIMEOUT):
    req = urllib.request.Request(url, headers={"User-Agent": "ardvane-feed"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as e:
        raise FeedError("no feed published yet" if e.code == 404 else f"GitHub returned HTTP {e.code}")
    except (urllib.error.URLError, OSError) as e:
        raise FeedError(f"no connection ({getattr(e, 'reason', e)})")


def update(url=FEED_URL, timeout=TIMEOUT):
    """Download, verify and store a newer feed. Returns (status, feed): status is "updated" or "current".
    Raises FeedError when nothing could be updated; the last good copy stays in place either way."""
    blob = download(url, timeout)
    new = parse(blob)
    old = cached()
    if old and new["sequence"] < old["sequence"]:
        raise FeedError(f"refusing an older feed (#{new['sequence']}, this computer has #{old['sequence']})")
    if old and new["sequence"] == old["sequence"]:
        return "current", old
    write_atomic(CACHE, blob)
    return "updated", new


def summary(feed):
    count = sum(len(feed[k]) for k in LIMITS)
    return f"the list from {feed['published'] or 'an unknown date'} ({count} indicators)"


def main(argv):
    safe_output()
    cmd = argv[0] if argv else ""
    if cmd == "update":
        try:
            status, feed = update()
        except FeedError as e:
            old = cached()
            print(f"detection feed: could not update ({e})" + (f"; still using {summary(old)}" if old else ""))
            return 1
        if "--quiet" not in argv or status == "updated":
            print(f"detection feed: {'updated to' if status == 'updated' else 'up to date,'} {summary(feed)}")
        return 0
    if cmd == "show":
        feed = cached()
        print(f"detection feed: {summary(feed)}" if feed else "detection feed: none yet (run: feed.py update)")
        if feed and "--json" in argv:
            print(json.dumps(feed))
        return 0
    print(__doc__)
    return 0 if cmd in ("-h", "--help") else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
