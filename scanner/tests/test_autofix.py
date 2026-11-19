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


# Synthetic samples, assembled at runtime so this file never contains a marker literally
G_BANG = "global['" + "!']='9-6489-1';"
OBF = "function _0x" + "3327(_0x439fc1,_0x1bf3f1){while(!![]){}}"
CONFIG = "module.exports = {\n  content: ['./src/**/*.js'],\n  plugins: [],\n};\n"
TAGS = "".join(chr(0xE0020 + i % 90) for i in range(40))


class Cleanups(Base):
    """An infected project is cleaned, not moved away: only the malicious parts go, the rest of the project stays."""

    def project(self):
        root = os.path.join(SANDBOX, "code", "shop")
        os.makedirs(os.path.join(root, "public", "fonts"))
        files = {
            "tailwind.config.js": CONFIG.replace("};\n", "};" + " " * 180 + G_BANG + "x" * 900 + "\n"),
            "public/fonts/fa-solid-900.woff2": OBF + "\n",
            ".gitignore": "node_modules\ntemp_auto_" + "push.bat\n.env\n",
            "package.json": json.dumps({"name": "shop", "scripts": {"preinstall": "node setup_" + "bun.js", "dev": "next dev"},
                                        "dependencies": {"next": "15.0.0"}}, indent=2) + "\n",
            "CLAUDE.md": "# Shop\nUse pnpm." + TAGS + "\n",
            "src/index.js": "console.log('shop');\n",
        }
        for rel, text in files.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(text)
        return root

    def scan(self, root):
        cr = kitlib.load_checkrepo()
        s = cr.Scan(root)
        s.walk()
        return sorted((f[1], f[2]) for f in s.findings if f[0] == "DANGER")

    def test_each_malicious_part_gets_its_own_fix_and_none_moves_the_project_automatically(self):
        root = self.project()
        offered = {f["target"]: f for f in autofix.detect([root]) if f["target"].startswith(root)}
        self.assertEqual(offered[os.path.join(root, "tailwind.config.js")]["how"], "hidden")
        self.assertEqual(offered[os.path.join(root, ".gitignore")]["how"], "gitignore")
        self.assertEqual(offered[os.path.join(root, "package.json")]["how"], "scripts")
        self.assertEqual(offered[os.path.join(root, "CLAUDE.md")]["how"], "invisible")
        self.assertEqual(offered[os.path.join(root, "public", "fonts", "fa-solid-900.woff2")]["kind"], "quarantine")
        self.assertFalse(offered[root]["clean"], "moving a whole project is never automatic")
        self.assertTrue(all(f["clean"] and not f["auto"] for t, f in offered.items() if t != root))

    def test_all_mode_cleans_the_project_and_keeps_everything_else(self):
        root = self.project()
        kitlib.write_json(kitlib.SETTINGS, {"autofix": "auto"})
        autofix.apply_auto([root])
        self.assertTrue(self.scan(root), "Automatic (safe fixes only) leaves projects alone")
        kitlib.write_json(kitlib.SETTINGS, {"autofix": "all"})
        done = autofix.apply_auto([root])
        self.assertTrue(done and all(e["ok"] for e in done), done)
        self.assertEqual(self.scan(root), [], "nothing malicious is left")
        self.assertTrue(os.path.isdir(root), "the project itself stays")
        with open(os.path.join(root, "tailwind.config.js"), encoding="utf-8") as f:
            self.assertEqual(f.read(), CONFIG, "the config is exactly what it was before the malware")
        with open(os.path.join(root, ".gitignore"), encoding="utf-8") as f:
            self.assertEqual(f.read(), "node_modules\n.env\n")
        with open(os.path.join(root, "package.json"), encoding="utf-8") as f:
            pkg = json.load(f)
        self.assertEqual(pkg["scripts"], {"dev": "next dev"})
        self.assertEqual(pkg["dependencies"], {"next": "15.0.0"})
        with open(os.path.join(root, "CLAUDE.md"), encoding="utf-8") as f:
            self.assertEqual(f.read(), "# Shop\nUse pnpm.\n")
        self.assertFalse(os.path.exists(os.path.join(root, "public", "fonts", "fa-solid-900.woff2")))

    def test_every_cleanup_can_be_undone(self):
        root = self.project()
        cfg = os.path.join(root, "tailwind.config.js")
        with open(cfg, encoding="utf-8") as f:
            infected = f.read()
        fid = next(f["id"] for f in autofix.detect([root]) if f["target"] == cfg)
        e = autofix.apply(fid, "manual", [root])
        self.assertTrue(e["ok"] and e["verified"], e)
        autofix.undo(e["id"])
        with open(cfg, encoding="utf-8") as f:
            self.assertEqual(f.read(), infected, "undo puts the original file back")
        self.assertTrue(os.path.isfile(os.path.join(e["undo"]["folder"], "manifest.json")))

    def test_a_file_that_is_all_malware_is_quarantined_whole(self):
        root = os.path.join(SANDBOX, "code", "dl")
        os.makedirs(root)
        with open(os.path.join(root, "api.js"), "w") as f:
            f.write(G_BANG + OBF + "\n")
        fixes = [f for f in autofix.detect([root]) if f["target"] == os.path.join(root, "api.js")]
        self.assertEqual([f["kind"] for f in fixes], ["quarantine"])

    @unittest.skipIf(os.name == "nt", "symlinks need extra rights on Windows")
    def test_a_link_out_of_the_project_is_never_edited(self):
        root = os.path.join(SANDBOX, "code", "linky")
        os.makedirs(root)
        outside = os.path.join(SANDBOX, "notes.js")
        with open(outside, "w") as f:
            f.write(CONFIG.replace("};\n", "};" + " " * 180 + G_BANG + "x" * 900 + "\n"))
        os.symlink(outside, os.path.join(root, "tailwind.config.js"))
        self.assertEqual([f for f in autofix.detect([root]) if f["target"].startswith(root) and f["target"] != root], [])

    @unittest.skipIf(os.name == "nt", "shell start-up files are macOS / Linux")
    def test_all_mode_removes_the_sabotage_line_and_malicious_extension(self):
        rc = os.path.join(SANDBOX, ".zshrc")
        with open(rc, "w") as f:
            f.write("export A=1\n# sudo shutdown -h 0 is how you'd stop it\nsudo shutdown -h 0\nalias l=ls\n")
        ext = os.path.join(SANDBOX, ".vscode", "extensions", "floktokbok.autoimport-1.0.0")
        os.makedirs(ext)
        with open(os.path.join(ext, "package.json"), "w") as f:
            json.dump({"publisher": "floktokbok", "name": "autoimport", "version": "1.0.0"}, f)
        kitlib.write_json(kitlib.SETTINGS, {"autofix": "all"})
        done = autofix.apply_auto()
        self.assertTrue(all(e["ok"] for e in done), done)
        with open(rc) as f:
            self.assertEqual(f.read(), "export A=1\n# sudo shutdown -h 0 is how you'd stop it\nalias l=ls\n")
        self.assertFalse(os.path.exists(ext))

    def test_ask_and_off_never_clean_anything(self):
        root = self.project()
        for mode in ("ask", "off"):
            kitlib.write_json(kitlib.SETTINGS, {"autofix": mode})
            with self.assertRaises(PermissionError):
                autofix.apply_auto([root])
        fid = next(f["id"] for f in autofix.detect([root]) if f["target"] == os.path.join(root, ".gitignore"))
        with self.assertRaises(PermissionError):
            autofix.apply(fid, "auto", [root])                     # "Automatic" (safe only) can't run a cleanup either


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
