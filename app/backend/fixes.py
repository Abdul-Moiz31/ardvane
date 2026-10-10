"""Fixes for the dashboard. The work is done by scanner/autofix.py (the same file the daily check uses), so there is
exactly one implementation of every fix and its safety checks."""
import importlib.util
import os
import sys
import threading

from .config import KIT
from . import settings

_module = None
_load_lock = threading.Lock()


def autofix():
    """scanner/autofix.py, loaded once (requests arrive on several threads at the same time)."""
    global _module
    with _load_lock:
        return _module or _load()


def _load():
    global _module
    scanner = os.path.join(KIT, "scanner")
    sys.path.insert(0, scanner)                                  # autofix imports kitlib next to it
    spec = importlib.util.spec_from_file_location("autofix", os.path.join(scanner, "autofix.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _module = module                                             # published only once fully loaded
    return _module


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
