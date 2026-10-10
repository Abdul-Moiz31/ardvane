"""The app icon that opens the dashboard: ~/Applications on macOS, the Start menu on Windows, the menu on Linux.

The icon is created on this computer (not downloaded), so it carries no quarantine flag and needs no code signing.
"""
import os
import plistlib
import shlex
import shutil

from .config import APP_DIR, APP_ID, APP_NAME, HOME, INSTALLED, IS_MAC, IS_WIN, KIT, UI, VERSION
from .system import python_exe, run

ENTRY = os.path.join(APP_DIR, "dashboard.py")


def installed_command():
    """Path of the `ardvane` command when Ardvane was installed with pipx / Homebrew (a stable path across upgrades)."""
    return shutil.which("ardvane") if INSTALLED else None


def path():
    if IS_MAC:
        return os.path.join(HOME, "Applications", APP_NAME + ".app")
    if IS_WIN:
        return os.path.join(os.environ.get("APPDATA", HOME), "Microsoft", "Windows", "Start Menu", "Programs", APP_NAME + ".lnk")
    return os.path.join(HOME, ".local", "share", "applications", APP_ID + ".desktop")


def installed():
    return os.path.exists(path())


def _mac():
    bundle = path()
    macos, resources = os.path.join(bundle, "Contents", "MacOS"), os.path.join(bundle, "Contents", "Resources")
    os.makedirs(macos, exist_ok=True)
    os.makedirs(resources, exist_ok=True)
    command = installed_command()
    if command:      # installed: the `ardvane` command finds its own Python
        script = f"#!/bin/sh\n# Opens the {APP_NAME} dashboard\n{shlex.quote(command)} >/dev/null 2>&1 &\n"
    else:            # a clone: try the Python that created the icon first, then the usual places
        candidates = " ".join(shlex.quote(c) for c in [python_exe(), "/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"])
        script = (f"#!/bin/sh\n# Opens the {APP_NAME} dashboard\n"
                  f"for p in {candidates}; do\n"
                  f"  if [ -x \"$p\" ]; then ARDVANE_KIT={shlex.quote(KIT)} \"$p\" {shlex.quote(ENTRY)} >/dev/null 2>&1 & exit 0; fi\n"
                  "done\n"
                  "osascript -e 'display alert \"Python 3 was not found\" message \"Install it with: xcode-select --install\"'\n")
    exe = os.path.join(macos, APP_ID)
    with open(exe, "w", encoding="utf-8") as f:
        f.write(script)
    os.chmod(exe, 0o755)
    icon_ok = run(["sips", "-s", "format", "icns", os.path.join(UI, "icon.png"), "--out",
                   os.path.join(resources, "AppIcon.icns")], timeout=60)[0] == 0
    info = {"CFBundleName": APP_NAME, "CFBundleDisplayName": APP_NAME, "CFBundleIdentifier": "dev.ardvane.dashboard",
            "CFBundleExecutable": APP_ID, "CFBundlePackageType": "APPL", "CFBundleShortVersionString": VERSION,
            "LSUIElement": True, "LSMinimumSystemVersion": "10.13"}
    if icon_ok:
        info["CFBundleIconFile"] = "AppIcon"
    with open(os.path.join(bundle, "Contents", "Info.plist"), "wb") as f:
        plistlib.dump(info, f)
    run(["touch", bundle], timeout=10)          # make Finder pick up the icon
    return 0, f"Added {APP_NAME} to your Applications folder. Open it from Launchpad, or press ⌘ Space and type {APP_NAME}."


def _windows():
    py = python_exe()
    pyw = os.path.join(os.path.dirname(py), "pythonw.exe")             # no console window
    ps = ("$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:LNK); $s.TargetPath = $env:EXE; "
          "$s.Arguments = $env:ARGS; $s.WorkingDirectory = $env:KITDIR; "
          "if (Test-Path $env:ICO) { $s.IconLocation = $env:ICO }; $s.Description = $env:DESC; $s.Save()")
    args = "-m ardvane" if INSTALLED else '"' + ENTRY + '"'          # installed: run the package with the same Python
    env = dict(os.environ, LNK=path(), EXE=pyw if os.path.isfile(pyw) else py, ARGS=args, KITDIR=KIT,
               ICO=os.path.join(UI, "icon.ico"), DESC=f"Open the {APP_NAME} dashboard")
    code, out = run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], timeout=60, env=env)
    return (0, f"Added {APP_NAME} to your Start menu.") if code == 0 else (code, out)


def _linux():
    quote = lambda s: '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    os.makedirs(os.path.dirname(path()), exist_ok=True)
    with open(path(), "w", encoding="utf-8") as f:
        f.write(f"[Desktop Entry]\nType=Application\nName={APP_NAME}\nComment=Malware protection dashboard\n"
                f"Exec={' '.join(quote(c) for c in ([installed_command()] if installed_command() else [python_exe(), ENTRY]))}\nIcon={os.path.join(UI, 'icon.png')}\nTerminal=false\n"
                "Categories=Utility;Security;\n")
    return 0, f"Added {APP_NAME} to your applications menu."


def install():
    return _mac() if IS_MAC else _windows() if IS_WIN else _linux()


def remove():
    target = path()
    if os.path.isdir(target):
        shutil.rmtree(target, ignore_errors=True)
    elif os.path.exists(target):
        os.remove(target)
    return 0, f"Removed the {APP_NAME} icon."
