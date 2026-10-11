"""The kit's own tools in scanner/ (autofix.py, github_check.py), loaded once and shared, so the dashboard runs
exactly the code the daily check and the command line run - one implementation of every fix and every check."""
import importlib.util
import os
import sys
import threading

from .config import KIT

_modules = {}
_lock = threading.Lock()          # requests arrive on several threads at the same time


def module(name):
    """scanner/<name>.py as a module."""
    with _lock:
        if name not in _modules:
            scanner = os.path.join(KIT, "scanner")
            if scanner not in sys.path:
                sys.path.insert(0, scanner)                    # the tools import kitlib next to them
            spec = importlib.util.spec_from_file_location(name, os.path.join(scanner, name + ".py"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _modules[name] = mod                               # published only once fully loaded
        return _modules[name]
