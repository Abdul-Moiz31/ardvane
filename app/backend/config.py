"""Names, paths and constants shared by the whole backend."""
import os
import sys

APP_NAME = "Ardvane"                      # the product name lives here and in ui/index.html
APP_ID = "ardvane"
VERSION = "0.1.0"

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KIT = os.environ.get("POLINRIDER_KIT") or os.path.dirname(APP_DIR)
UI = os.path.join(APP_DIR, "ui")

HOME = os.path.expanduser("~")
DEST = os.path.join(HOME, ".checkrepo")                 # where the installer puts the scanner, hooks and reports
REPORTS = os.path.join(DEST, "reports")
SCANS = os.path.join(REPORTS, "scans")
SETTINGS = os.path.join(DEST, "settings.json")
PROJECTS = os.path.join(DEST, "projects.txt")
INSTANCE = os.path.join(DEST, "dashboard.json")
TASKS = os.path.join(DEST, "tasks.json")

IS_WIN = os.name == "nt"
IS_MAC = sys.platform == "darwin"
OS_NAME = "windows" if IS_WIN else "mac" if IS_MAC else "linux"

ROUTINE_LABEL = "com.polinrider-survival-kit.daily-check"      # macOS launchd job (mac/install-routine.sh)
ROUTINE_TASK = "polinrider-survival-kit daily check"           # Windows scheduled task (windows/install-routine.ps1)
RC_MARKER = "# >>> polinrider-survival-kit >>>"                # block the installer adds to shell profiles

IDLE_LIMIT = 300            # seconds without a request from the tab before the dashboard stops itself
DEFAULT_FOLDERS = ["~/Documents", "~/Desktop", "~/Downloads", "~/code", "~/projects"] + (["~/source/repos"] if IS_WIN else [])
