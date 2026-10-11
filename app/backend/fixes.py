"""Fixes for the dashboard. The work is done by scanner/autofix.py (the same file the daily check uses), so there is
exactly one implementation of every fix and its safety checks."""
from . import kit, settings


def autofix():
    return kit.module("autofix")


def mode():
    return settings.load()["autofix"]


def overview(projects=()):
    af = autofix()
    current = mode()
    return {"mode": current, "available": af.detect(projects) if current != "off" else [], "history": af.history()[:50]}


def apply(fix_id, projects=()):
    return autofix().apply(fix_id, "manual", projects)


def apply_auto_if_enabled():
    """After a scan: apply auto-safe fixes when the user chose Automatic. Returns the history entries."""
    return autofix().apply_auto() if mode() == "auto" else []


def undo(entry_id):
    return autofix().undo(entry_id)
