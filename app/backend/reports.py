"""Daily-check and scan reports kept in ~/.checkrepo/reports (read-only)."""
import os
import re

from .config import REPORTS, SCANS
from .system import ANSI, read_text

DAILY_RE = re.compile(r"\d{4}-\d{2}-\d{2}\.txt")
SCAN_RE = re.compile(r"scan-report-\d{4}-\d{2}-\d{2}-\d{4}\.txt")
FOLDERS = {"daily": (REPORTS, DAILY_RE), "scan": (SCANS, SCAN_RE)}
# Finding lines written by the macOS/Linux scripts (emoji) and the Windows scripts (ASCII)
FINDING_RE = re.compile(r"^\s*(🛑|\[DANGER\]|⚠️|\[CHECK\])\s*(.+?)\s*$", re.M)


def level_of(verdict):
    if re.match(r"(?:ACTION NEEDED|INFECTED)", verdict):
        return "danger"
    if "worth a look" in verdict:
        return "warn"
    if re.match(r"(?:ALL CLEAN|CLEAN)", verdict):
        return "ok"
    return "unknown"


def summarize(text):
    m = re.search(r"^(?:VERDICT|RESULT): ?(.*)$", text, re.M)
    verdict = m.group(1).strip() if m else ""
    levels = [level for level, _ in findings(text)]
    return {"verdict": verdict, "level": level_of(verdict), "danger": levels.count("danger"), "warn": levels.count("warn")}


def findings(text):
    """[(level, message)] for every DANGER / CHECK line of a report."""
    return [("danger" if m.group(1) in ("🛑", "[DANGER]") else "warn", m.group(2)) for m in FINDING_RE.finditer(text)]


def list_all(limit=400):
    rows = []
    for kind, (folder, pattern) in FOLDERS.items():
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        for name in names:
            if not pattern.fullmatch(name):
                continue
            full = os.path.join(folder, name)
            text = read_text(full, 400_000)
            if text is None:
                continue
            row = {"id": f"{kind}:{name}", "kind": kind, "time": os.path.getmtime(full)}
            row.update(summarize(text))
            rows.append(row)
    rows.sort(key=lambda r: r["time"], reverse=True)
    return rows[:limit]


def latest_daily():
    rows = [r for r in list_all() if r["kind"] == "daily"]
    return rows[0] if rows else None


def read(report_id):
    """Text of one report, or None. The id is validated against the known file-name patterns."""
    kind, _, name = str(report_id).partition(":")
    if kind not in FOLDERS or not FOLDERS[kind][1].fullmatch(name):
        return None
    text = read_text(os.path.join(FOLDERS[kind][0], name))
    return ANSI.sub("", text) if text is not None else None
