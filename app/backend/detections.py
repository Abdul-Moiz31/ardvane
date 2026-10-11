"""The signed detection feed (scanner/feed.py) for the dashboard: what this computer has, and updating it.
Everything - download, signature check, rollback protection - is done by feed.py, the same code the daily check runs."""
from . import kit


def status():
    """{sequence, published, count} of the feed on this computer, or None before the first update."""
    feed = kit.module("feed")
    f = feed.cached()
    return {"sequence": f["sequence"], "published": f["published"], "count": sum(len(f[k]) for k in feed.LIMITS)} if f else None


def update():
    """Fetch a newer feed if there is one. Returns {ok, message}; never raises for network or feed problems."""
    feed = kit.module("feed")
    try:
        state, f = feed.update()
    except feed.FeedError as e:
        old = feed.cached()
        return {"ok": False, "message": f"Couldn't update detections ({e})" + (f" - still using {feed.summary(old)}" if old else "")}
    return {"ok": True, "message": ("Detections updated to " if state == "updated" else "Detections are up to date: ") + feed.summary(f)}
