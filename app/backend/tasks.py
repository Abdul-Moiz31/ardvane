"""The to-do list: turns findings into concrete steps and keeps asking until they are done.

Rules
  * Every DANGER and every un-hidden WARNING becomes a task with steps (tasks_catalog.FINDING_RULES).
  * The first DANGER also opens the recovery checklist (tasks_catalog.INCIDENT), in the guide's order.
  * Marked a finding as fixed, but a later scan or daily check still finds it? The task reopens and says so.
  * Setup tasks complete themselves when the protection they ask for is on, and reopen if it's switched off.
  * Routine checks come back every N days.

Only progress is stored (~/.checkrepo/tasks.json); titles and steps always come from the catalog.
"""
import json
import threading
import time

from . import reports
from .config import TASKS
from .system import read_json, short_hash, write_private
from .tasks_catalog import INCIDENT, RECURRING, SETUP, rule_for

_lock = threading.Lock()
DAY = 86400
CATALOG = {t["id"]: t for t in INCIDENT + SETUP + RECURRING}
POSITION = {tid: i for i, tid in enumerate(CATALOG)}          # keep the catalog's (= the guide's) order
GROUP_OF = dict([(t["id"], "incident") for t in INCIDENT] + [(t["id"], "setup") for t in SETUP] + [(t["id"], "routine") for t in RECURRING])


def _load():
    data = read_json(TASKS, {})
    return {"tasks": data.get("tasks") if isinstance(data.get("tasks"), dict) else {}}


def _save(data):
    write_private(TASKS, json.dumps(data, indent=1) + "\n")


def _when(ts):
    return time.strftime("%d %b %Y", time.localtime(ts))


def finding(level, text, path="", seen=0.0):
    """A finding as the to-do list sees it. The key matches the scan's own key, so hiding a warning works everywhere."""
    return {"key": short_hash(text), "level": level, "text": text, "path": path, "seen": seen}


def findings_from_reports():
    """Findings in the newest daily check and the newest scan report (older reports are history, not to-dos)."""
    out = []
    for kind in ("daily", "scan"):
        latest = next((r for r in reports.list_all() if r["kind"] == kind), None)
        text = reports.read(latest["id"]) if latest else None
        for level, line in reports.findings(text or ""):
            out.append(finding(level, line, seen=latest["time"]))
    return out


def sync(found, protection, dismissed, now=None):
    """Bring the list up to date with the latest findings and protection status. Safe to call often."""
    now = now or time.time()
    with _lock:
        data = _load()
        tasks = data["tasks"]
        changed = False

        for f in found:
            if f["level"] not in ("danger", "warn"):
                continue
            tid = "f-" + f["key"]
            t = tasks.get(tid)
            hidden = f["level"] == "warn" and f["key"] in dismissed
            if t is None:
                if hidden:
                    continue
                tasks[tid] = {"kind": "finding", "level": f["level"], "text": f["text"], "path": f["path"], "created": now,
                              "seen": f["seen"], "steps_done": [], "done_at": None}
                changed = True
                continue
            if f["seen"] > t.get("seen", 0):
                t["seen"] = f["seen"]
                changed = True
                if t.get("done_at") and t.get("resolution") == "fixed" and f["seen"] > t["done_at"]:
                    t.update(done_at=None, resolution=None, steps_done=[],
                             reopened=f"You marked this done on {_when(t['done_at'])}, but the check on {_when(f['seen'])} still found it.")
            if hidden and not t.get("done_at"):
                t.update(done_at=now, resolution="mine")
                changed = True

        dangers = [f["seen"] for f in found if f["level"] == "danger"]
        if dangers:
            changed = _open_incident(tasks, max(dangers), now) or changed

        for t in SETUP:
            st = tasks.setdefault(t["id"], {"kind": "setup", "created": now, "steps_done": [], "done_at": None})
            auto = t.get("auto")
            if auto:
                on = bool(protection.get("installed") and protection.get("hooks")) if auto == "protection" else bool(protection.get("routine", {}).get("on"))
                if on and not st.get("done_at"):
                    st.update(done_at=now, resolution="auto")
                    changed = True
                elif not on and st.get("resolution") == "auto":
                    st.update(done_at=None, resolution=None)
                    changed = True

        for t in RECURRING:
            if t["id"] not in tasks:
                tasks[t["id"]] = {"kind": "routine", "created": now, "steps_done": [], "done_at": None}
                changed = True

        if changed or not read_json(TASKS, {}):
            _save(data)
        return data


def _open_incident(tasks, evidence_time, now):
    """Open the recovery checklist for evidence seen at `evidence_time` — unless it's already open, or was finished
    after that evidence. Returns True when the list changed."""
    existing = [tasks.get(t["id"]) for t in INCIDENT]
    finished = all(e and e.get("done_at") for e in existing)
    last_done = max((e["done_at"] for e in existing if e and e.get("done_at")), default=0)
    if any(e is None for e in existing) or (finished and evidence_time > last_done):
        for t in INCIDENT:
            tasks[t["id"]] = {"kind": "incident", "created": now, "steps_done": [], "done_at": None}
        return True
    return False


def start_incident():
    """Malware was removed from this computer: whatever it stole is still stolen, so recovery starts now."""
    with _lock:
        data = _load()
        now = time.time()
        if _open_incident(data["tasks"], now, now):
            _save(data)


def _view(tid, st, now):
    """Full task for the UI: catalog text + saved progress + computed status."""
    if st.get("kind") == "finding":
        rule = rule_for(st["level"], st["text"])
        level, title, detail, steps, link = st["level"], rule["title"], rule["detail"], rule["steps"], (rule.get("link") or "")
        group = "finding"
    else:
        c = CATALOG.get(tid)
        if c is None:
            return None
        group = GROUP_OF[tid]
        level = "danger" if group == "incident" else "info"
        title, detail, steps, link = c["title"], c["detail"], c["steps"], c.get("link", "")
    done = set(st.get("steps_done") or [])
    view = {"id": tid, "group": group, "level": level, "title": title, "detail": detail, "link": link,
            "steps": [{"text": s, "link": l, "done": i in done} for i, (s, l) in enumerate(steps)],
            "finding": st.get("text", ""), "path": st.get("path", ""), "created": st.get("created"),
            "done_at": st.get("done_at"), "resolution": st.get("resolution"), "reopened": st.get("reopened", ""),
            "status": "done" if st.get("done_at") else "open", "due_at": None, "auto": bool(CATALOG.get(tid, {}).get("auto"))}
    if group == "routine":
        every = CATALOG[tid]["every_days"]
        last = st.get("done_at")
        view["every_days"] = every
        view["due_at"] = (last + every * DAY) if last else st.get("created")
        view["status"] = "open" if not last or now >= view["due_at"] else "scheduled"
    return view


ORDER = {"incident": 0, "finding": 1, "setup": 2, "routine": 3}
LEVEL_ORDER = {"danger": 0, "warn": 1, "info": 2}


def overview(data, now=None):
    now = now or time.time()
    views = [v for v in (_view(tid, st, now) for tid, st in data["tasks"].items()) if v]
    views.sort(key=lambda v: (ORDER[v["group"]], LEVEL_ORDER.get(v["level"], 3), POSITION.get(v["id"], -v["created"] or 0)))
    open_ = [v for v in views if v["status"] == "open"]
    incident = [v for v in views if v["group"] == "incident"]
    return {"tasks": views,
            "counts": {"open": len(open_), "danger": sum(1 for v in open_ if v["level"] == "danger"),
                       "warn": sum(1 for v in open_ if v["level"] == "warn"),
                       "incident_total": len(incident), "incident_done": sum(1 for v in incident if v["status"] == "done")}}


def _update(tid, fn):
    with _lock:
        data = _load()
        st = data["tasks"].get(tid)
        if st is None:
            raise KeyError(tid)
        fn(st)
        _save(data)


def set_step(tid, index, done):
    view = _view(tid, _load()["tasks"].get(tid) or {}, time.time())
    if view is None or not 0 <= index < len(view["steps"]):
        raise KeyError(tid)

    def apply(st):
        steps = set(st.get("steps_done") or [])
        steps.add(index) if done else steps.discard(index)
        st["steps_done"] = sorted(steps)
    _update(tid, apply)


def resolve_path(path):
    """A fix removed `path`: close the open to-do items about it. A later scan reopens them if it's still there."""
    with _lock:
        data = _load()
        for st in data["tasks"].values():
            if st.get("kind") == "finding" and st.get("path") == path and not st.get("done_at"):
                st.update(done_at=time.time(), resolution="fixed")
        _save(data)


def set_done(tid, done, resolution="fixed"):
    def apply(st):
        if done:
            st.update(done_at=time.time(), resolution=resolution, reopened="")
            if st.get("kind") == "routine":
                st["steps_done"] = []          # start fresh next time it's due
        else:
            st.update(done_at=None, resolution=None)
    _update(tid, apply)
