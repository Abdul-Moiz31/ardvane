#!/usr/bin/env python3
"""Build Ardvane's detection feed from feed/indicators.json.

    python3 .github/scripts/build_feed.py --check         validate every entry (CI, every pull request)
    python3 .github/scripts/build_feed.py --out FILE      write the feed body the feed workflow signs

Entries are checked by scanner/feed.py itself - the same rules every installed Ardvane applies to the feed - so a
pull request can't merge an entry the app would refuse. The sequence number is the build time, so each published
feed is newer than the last.
"""
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scanner"))
import feed    # noqa: E402

SOURCE = os.path.join(ROOT, "feed", "indicators.json")


def build(now=None):
    with open(SOURCE, encoding="utf-8") as f:
        src = json.load(f)
    unknown = set(src) - set(feed.LIMITS) - {"_about"}
    if unknown:
        sys.exit(f"{SOURCE}: unknown lists {sorted(unknown)} (allowed: {sorted(feed.LIMITS)})")
    now = int(now or time.time())
    body = {"schema": feed.SCHEMA, "sequence": now, "published": time.strftime("%Y-%m-%d", time.gmtime(now))}
    for key, limit in feed.LIMITS.items():
        values = src.get(key, [])
        if not isinstance(values, list) or len(values) > limit:
            sys.exit(f"'{key}' must be a list of at most {limit} entries")
        bad = [v for v in values if not feed._check_entry(key, v)]
        if bad:
            sys.exit(f"'{key}': {len(bad)} entr{'y is' if len(bad) == 1 else 'ies are'} not allowed: {bad[:5]}")
        body[key] = sorted(set(values))
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")


def main(argv):
    body = build()
    counts = {k: len(v) for k, v in json.loads(body).items() if isinstance(v, list)}
    if "--out" in argv:
        out = argv[argv.index("--out") + 1]
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "wb") as f:
            f.write(body)
    print(f"detection feed: {sum(counts.values())} indicators {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
