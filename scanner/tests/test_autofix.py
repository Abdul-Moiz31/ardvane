"""Tests for autofix.py, in a throw-away home folder.  Run:  python3 scanner/tests/test_autofix.py

Includes attempts to trick the fixer into moving things it must never touch.
"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

SANDBOX = os.path.realpath(tempfile.mkdtemp(prefix="autofix-test-"))
for var, sub in (("HOME", ""), ("USERPROFILE", ""), ("APPDATA", "AppData/Roaming"), ("LOCALAPPDATA", "AppData/Local")):
    os.environ[var] = os.path.join(SANDBOX, sub) if sub else SANDBOX        # before the modules compute their paths
HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(KIT, "scanner"))

import autofix  # noqa: E402
import kitlib   # noqa: E402

N2 = os.path.join(SANDBOX, ".n2")
SSH = os.path.join(SANDBOX, ".ssh")


def ids(items):
    return {f["id"] for f in items}


class Base(unittest.TestCase):
    def setUp(self):
        for name in os.listdir(SANDBOX):
            p = os.path.join(SANDBOX, name)
            if os.path.islink(p) or os.path.isfile(p):
                os.remove(p)
            else:
                shutil.rmtree(p, ignore_errors=True)
        os.makedirs(SSH)
        with open(os.path.join(SSH, "id_ed25519"), "w") as f:
            f.write("secret key")

    def plant_n2(self):
        os.makedirs(N2)
        payload = os.path.join(N2, "payload.sh")
        with open(payload, "w") as f:
            f.write("#!/bin/sh\necho stolen\n")
        os.chmod(payload, 0o755)
        return payload


class Quarantine(Base):
    def test_known_location_is_quarantined_neutralised_and_restorable(self):
        payload = self.plant_n2()
        fid = "path:" + autofix.short(N2)
        self.assertIn(fid, ids(autofix.detect()))
        e = autofix.apply(fid)
        self.assertTrue(e["ok"] and e["verified"], e)
        self.assertFalse(os.path.exists(N2))
        moved = os.path.join(e["undo"]["folder"], "item", "payload.sh")
        self.assertTrue(os.path.isfile(moved), "moved, never deleted")
        if os.name != "nt":
            self.assertFalse(os.stat(moved).st_mode & stat.S_IXUSR, "quarantined files can't be run")
        manifest = kitlib.read_json(os.path.join(e["undo"]["folder"], "manifest.json"), {})
        self.assertEqual(manifest["original"], N2)
        autofix.undo(e["id"])
        self.assertTrue(os.path.isfile(payload))
        if os.name != "nt":
            self.assertTrue(os.stat(payload).st_mode & stat.S_IXUSR, "undo restores the original permissions")
        with self.assertRaises(LookupError):
            autofix.undo(e["id"])                         # can't undo twice

    @unittest.skipIf(os.name == "nt", "symlinks need extra rights on Windows")
    def test_symlink_to_ssh_moves_only_the_link(self):
        os.symlink(SSH, N2)
        e = autofix.apply("path:" + autofix.short(N2))
        self.assertTrue(e["ok"], e)
        self.assertTrue(os.path.isfile(os.path.join(SSH, "id_ed25519")), "~/.ssh must be untouched")
        self.assertTrue(os.path.islink(os.path.join(e["undo"]["folder"], "item")))

    def test_protected_and_outside_paths_are_refused(self):
        for bad in (SANDBOX, SSH, os.path.join(SSH, "id_ed25519"), kitlib.DEST, os.path.join(SANDBOX, "Library"),
                    "/etc/hosts" if os.name != "nt" else os.environ.get("SystemRoot", "C:\\Windows")):
            if not os.path.lexists(bad):
                os.makedirs(bad, exist_ok=True)
            with self.assertRaises(ValueError, msg=bad):
                autofix.check_movable(bad)

    @unittest.skipIf(os.name == "nt", "symlinks need extra rights on Windows")
    def test_parent_symlink_into_protected_folder_is_refused(self):
        os.symlink(SSH, os.path.join(SANDBOX, "innocent"))
        with self.assertRaises(ValueError):
            autofix.check_movable(os.path.join(SANDBOX, "innocent", "id_ed25519"))
        self.assertTrue(os.path.isfile(os.path.join(SSH, "id_ed25519")))

    def test_unknown_or_stale_ids_do_nothing(self):
        with self.assertRaises(LookupError):
            autofix.apply("path:" + autofix.short(SSH))      # forged id for a path that isn't on the list
        with self.assertRaises(LookupError):
            autofix.apply("path:" + autofix.short(N2))       # on the list, but nothing there


class Modes(Base):
    def test_auto_needs_the_setting_and_never_runs_ask_only_fixes(self):
        self.plant_n2()
        node_modules = os.path.join(SANDBOX, ".node_modules")          # "ask" in malware-paths.txt
        os.makedirs(node_modules)
        with self.assertRaises(PermissionError):
            autofix.apply_auto()                                         # default mode is "ask"
        kitlib.write_json(kitlib.SETTINGS, {"autofix": "auto"})
        with self.assertRaises(PermissionError):
            autofix.apply("path:" + autofix.short(node_modules), "auto")
        done = autofix.apply_auto()
        self.assertIn("path:" + autofix.short(N2), {e["fix"] for e in done})
        self.assertFalse(os.path.exists(N2))
        self.assertTrue(os.path.isdir(node_modules), "ask-only items stay until a person confirms")


class Editors(Base):
    def folder(self):
        if os.name == "nt":
            return os.path.join(os.environ["APPDATA"], "Code", "User")
        if sys.platform == "darwin":
            return os.path.join(SANDBOX, "Library", "Application Support", "Code", "User")
        return os.path.join(SANDBOX, ".config", "Code", "User")

    def test_editor_fix_and_undo(self):
        os.makedirs(self.folder())
        path = os.path.join(self.folder(), "settings.json")
        original = {"editor.fontSize": 14, "task.allowAutomaticTasks": "on"}
        with open(path, "w") as f:
            json.dump(original, f)
        e = autofix.apply("editor:Code")
        self.assertTrue(e["ok"] and e["verified"], e)
        with open(path) as f:
            fixed = json.load(f)
        self.assertEqual((fixed["task.allowAutomaticTasks"], fixed["editor.fontSize"]), ("off", 14))
        autofix.undo(e["id"])
        with open(path) as f:
            self.assertEqual(json.load(f), original)

    def test_settings_with_comments_are_left_for_a_person(self):
        os.makedirs(self.folder())
        with open(os.path.join(self.folder(), "settings.json"), "w") as f:
            f.write('{\n  // my comment\n  "task.allowAutomaticTasks": "on"\n}\n')
        self.assertNotIn("editor:Code", ids(autofix.detect_editors()))


class Processes(unittest.TestCase):
    def test_matches_malware_but_not_people_searching_for_it(self):
        fake = [(4242, "/Users/x/Library/Application Support/MicrosoftSystem64/MicrosoftSystem64 --daemon"),
                (4243, "grep MicrosoftSystem64"), (4244, "vim notes-about-SvcHostUpdate.txt"),
                (4245, "node /tmp/x/fa-solid-400.woff2"), (os.getpid(), "python MicrosoftSystem64"), (1, "MicrosoftSystem64")]
        found = autofix.detect_processes(fake)
        self.assertEqual(sorted(int(f["target"]) for f in found), [4242, 4245])
        self.assertTrue(all(not f["auto"] and not f["undoable"] for f in found), "stopping a process always asks")


@unittest.skipUnless(shutil.which("git"), "git not installed")
class Projects(Base):
    def test_only_projects_checkrepo_flags_now_are_offered(self):
        bad, good = os.path.join(SANDBOX, "code", "test-task"), os.path.join(SANDBOX, "code", "my-app")
        for d in (bad, good):
            os.makedirs(d)
            subprocess.run(["git", "init", "-q", d], check=True)
        with open(os.path.join(bad, ".gitignore"), "w") as f:
            f.write("temp_auto_" + "push.bat\n")                  # the worm's .gitignore entry, assembled at runtime
        offered = autofix.detect_projects([bad, good, SSH, SANDBOX])
        self.assertEqual([f["target"] for f in offered], [bad])
        self.assertFalse(offered[0]["auto"])
        e = autofix.apply(offered[0]["id"], "manual", [bad])
        self.assertTrue(e["ok"] and not os.path.exists(bad), e)


class ListsInSync(unittest.TestCase):
    """Every known malware path in the scan scripts is in lists/malware-paths.txt (one source of truth for fixes)."""

    def test_scripts_and_list_agree(self):
        with open(os.path.join(KIT, "scanner", "lists", "malware-paths.txt"), encoding="utf-8") as f:
            listed = {line.split(None, 2)[2].strip().replace("\\", "/").replace("%LOCALAPPDATA%", "LOCALAPPDATA")
                      for line in f if line.strip() and not line.startswith("#") and len(line.split(None, 2)) == 3}
        found = set()
        for script in ("scan-my-machine.sh", "mac/daily-check.sh"):
            with open(os.path.join(KIT, script), encoding="utf-8") as f:
                block = re.search(r"for p in (.*?); do", f.read(), re.S).group(1)       # the known-locations loop
            found |= {"~" + m for m in re.findall(r'"\$HOME(/[^"]+)"', block)} | set(re.findall(r"(/tmp/[^\s;]+)", block))
        for script in ("scan-my-machine.ps1", "windows/daily-check.ps1"):
            with open(os.path.join(KIT, script), encoding="utf-8") as f:
                block = re.search(r"@\(([^)]*\\\.n2[^)]*)\)", f.read(), re.S).group(1)  # the array that lists ~/.n2
            for var, rest in re.findall(r'"\$(env:LOCALAPPDATA|HOME)\\([^"]+)"', block):
                found.add(("LOCALAPPDATA/" if var == "env:LOCALAPPDATA" else "~/") + rest.replace("\\", "/"))
        self.assertGreater(len(found), 20, "the parser found the lists in the scripts")
        missing = {p for p in found if p not in listed}
        self.assertFalse(missing, f"add these to scanner/lists/malware-paths.txt: {sorted(missing)}")


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        shutil.rmtree(SANDBOX, ignore_errors=True)
