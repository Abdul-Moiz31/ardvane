"""Tests for safe install (scanner/safeinstall.py and scanner/shell/safe-install.sh). Offline: OSV.dev and npm are
replaced with stand-ins.  Run:  python3 scanner/tests/test_safeinstall.py"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(HERE, "..")
ROOT = os.path.join(SCANNER, "..")
os.environ["ARDVANE_NO_FEED"] = "1"               # built-in lists only, whatever feed this computer has
sys.path.insert(0, SCANNER)
import safeinstall as si   # noqa: E402

BAD_NPM = "tailwindcss-" + "animate-style"         # in the built-in list (assembled so this file holds no indicator)


def names(result):
    return sorted({(p.eco, p.name, p.version) for p in result})


class Planning(unittest.TestCase):
    """What a command would install."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ardvane-si-")
        self.saved = si.resolve_npm
        si.resolve_npm = lambda folder, specs, args: None          # no npm, no network

    def tearDown(self):
        si.resolve_npm = self.saved
        shutil.rmtree(self.dir, ignore_errors=True)

    def plan(self, tool, *args):
        p = si.plan(tool, list(args), self.dir)
        return None if p is None else names(p[0])

    def test_commands_that_install_nothing_pass_straight_through(self):
        for cmd in (("npm", "run", "dev"), ("npm", "test"), ("npm", "--version"), ("pnpm", "build"), ("yarn", "dev"),
                    ("pip", "list"), ("pip3", "freeze"), ("bun", "run", "x"), ("git", "clone", "x")):
            self.assertIsNone(self.plan(*cmd), cmd)

    def test_npm_package_specs(self):
        self.assertEqual(self.plan("npm", "install", "-D", "left-pad@1.3.0", "@types/node@^20", "alias@npm:real-pkg@2.0.0"),
                         [("npm", "@types/node", None), ("npm", "left-pad", "1.3.0"), ("npm", "real-pkg", "2.0.0")])
        # paths, URLs, git sources and option values are not packages
        self.assertEqual(self.plan("npm", "i", "./local", "../x", "file:../y", "git+https://x/y.git", "user/repo",
                                   "https://x.example/p.tgz", "--prefix", "somewhere", "-w", "web", "ok-pkg"),
                         [("npm", "ok-pkg", None)])

    def test_each_tool_reads_its_own_options(self):
        self.assertEqual(self.plan("pnpm", "add", "-r", "x-pkg"), [("npm", "x-pkg", None)])          # -r: recursive
        self.assertEqual(self.plan("pnpm", "-C", "web", "add", "y-pkg"), [("npm", "y-pkg", None)])
        self.assertEqual(self.plan("yarn"), [])                                                    # plain `yarn` installs
        self.assertEqual(self.plan("yarn", "add", "z-pkg"), [("npm", "z-pkg", None)])
        self.assertEqual(self.plan("bun", "a", "b-pkg"), [("npm", "b-pkg", None)])

    def test_packages_that_get_run(self):
        self.assertEqual(self.plan("npx", "create-thing@1.0.0", "my-app"), [("npm", "create-thing", "1.0.0")])
        self.assertEqual(self.plan("npx", "-p", "tool-a", "-p", "tool-b", "run-it"), [("npm", "tool-a", None), ("npm", "tool-b", None)])
        self.assertEqual(self.plan("npx", "--package=tool-c", "x"), [("npm", "tool-c", None)])
        self.assertEqual(self.plan("npm", "exec", "--", "runner-pkg"), [("npm", "runner-pkg", None)])
        self.assertEqual(self.plan("pnpm", "dlx", "dlx-pkg"), [("npm", "dlx-pkg", None)])

    def test_pip_names_and_requirement_files(self):
        with open(os.path.join(self.dir, "req.txt"), "w") as f:
            f.write("# comment\nFlask[async]==2.0.1\nrequests>=2  # http\n-r more.txt\n--index-url https://x\n")
        with open(os.path.join(self.dir, "more.txt"), "w") as f:
            f.write("Some_Package.Name==1.0\n")
        self.assertEqual(self.plan("pip", "install", "-r", "req.txt", "Django==5.0", "-e", ".", "--target", "dir"),
                         [("PyPI", "django", "5.0"), ("PyPI", "flask", "2.0.1"), ("PyPI", "requests", None),
                          ("PyPI", "some-package-name", "1.0")])
        self.assertEqual(self.plan("pip3", "install", "-rreq.txt")[0], ("PyPI", "flask", "2.0.1"))

    def test_lockfiles(self):
        lock = {"lockfileVersion": 3, "packages": {"": {"name": "app"},
                "node_modules/a-pkg": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a-pkg/-/a-pkg-1.0.0.tgz"},
                "node_modules/a-pkg/node_modules/b-pkg": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/b-pkg/-/b-pkg-2.0.0.tgz"},
                "node_modules/@corp/internal": {"version": "1.0.0", "resolved": "https://npm.corp.example/@corp/internal.tgz"},
                "packages/lib": {"version": "0.1.0"}, "node_modules/lib": {"link": True, "resolved": "packages/lib"}}}
        with open(os.path.join(self.dir, "package-lock.json"), "w") as f:
            json.dump(lock, f)
        pkgs = si.lockfile_packages(self.dir)
        self.assertEqual(sorted((p.name, p.version, p.public) for p in pkgs),
                         [("@corp/internal", "1.0.0", False), ("a-pkg", "1.0.0", True), ("b-pkg", "2.0.0", True)])
        os.remove(os.path.join(self.dir, "package-lock.json"))
        with open(os.path.join(self.dir, "pnpm-lock.yaml"), "w") as f:
            f.write("packages:\n  /c-pkg@3.1.0:\n    resolution: {}\n  '@s/d-pkg@4.0.0(react@18.2.0)':\n    x: y\n")
        self.assertEqual(sorted((p.name, p.version) for p in si.lockfile_packages(self.dir)),
                         [("@s/d-pkg", "4.0.0"), ("c-pkg", "3.1.0"), ("react", "18.2.0")])
        os.remove(os.path.join(self.dir, "pnpm-lock.yaml"))
        with open(os.path.join(self.dir, "yarn.lock"), "w") as f:
            f.write('"e-pkg@^1.0.0", "e-pkg@^1.2.0":\n  version "1.2.3"\n  resolved "x"\n\n"@s/f-pkg@npm:^2":\n  version: 2.0.1\n')
        self.assertEqual(sorted((p.name, p.version) for p in si.lockfile_packages(self.dir)), [("@s/f-pkg", "2.0.1"), ("e-pkg", "1.2.3")])


class Checking(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ardvane-si-")
        self.saved = si.resolve_npm, si.http_json, si.CACHE, si.load_cache
        si.resolve_npm = lambda folder, specs, args: None
        si.CACHE = os.path.join(self.dir, "osv-cache.json")
        self.sent, self.osv = [], {}
        si.http_json = self.fake_osv

    def tearDown(self):
        si.resolve_npm, si.http_json, si.CACHE, si.load_cache = self.saved
        shutil.rmtree(self.dir, ignore_errors=True)

    def fake_osv(self, url, body=None, timeout=0):
        """Stand-in for OSV.dev: self.osv maps package name -> list of advisory ids."""
        if url.startswith(si.OSV_VULN):
            mid = url[len(si.OSV_VULN):]
            if mid == "MAL-SOME":
                return {"affected": [{"versions": ["1.2.3"]}]}
            return {"affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
        self.sent += [q["package"]["name"] for q in body["queries"]]
        return {"results": [{"vulns": [{"id": i} for i in self.osv.get(q["package"]["name"], [])]} for q in body["queries"]]}

    def check(self, tool, *args, osv=True):
        b, w, notes, count = si.check(tool, list(args), self.dir, use_osv=osv)
        return sorted(p.name for p, _ in b), sorted(p.name for p, _ in w), notes

    def test_ardvane_list_blocks_offline(self):
        self.assertEqual(self.check("npm", "install", BAD_NPM, "react", osv=False)[0], [BAD_NPM])
        self.assertEqual(self.check("pip", "install", "PyBitJS==1.0", osv=False)[0], ["pybitjs"])      # PyPI name rules
        self.assertEqual(self.sent, [])

    def test_osv_malware_blocks_and_other_advisories_do_not(self):
        self.osv = {"evil-pkg": ["MAL-WHOLE"], "old-lib": ["GHSA-xxxx-yyyy-zzzz"]}
        self.assertEqual(self.check("npm", "install", "evil-pkg", "old-lib", "react")[0], ["evil-pkg"])

    def test_only_some_versions_malicious(self):
        self.osv = {"hijacked": ["MAL-SOME"]}
        self.assertEqual(self.check("npm", "install", "hijacked")[:2], ([], ["hijacked"]))           # version unknown: warn
        self.assertEqual(self.check("npm", "install", "hijacked@1.2.3")[0], ["hijacked"])            # exact version: block

    def test_private_packages_are_never_sent(self):
        with open(os.path.join(self.dir, ".npmrc"), "w") as f:
            f.write("@corp:registry=https://npm.corp.example/\n")
        self.check("npm", "install", "@corp/secret-thing", "public-pkg")
        self.assertEqual(self.sent, ["public-pkg"])
        self.sent = []
        _, _, notes = self.check("pip", "install", "--index-url", "https://pypi.corp.example/simple", "internal-pkg")
        self.assertEqual(self.sent, [])
        self.assertTrue(any("private registry" in n for n in notes))

    def test_answers_are_cached(self):
        self.check("npm", "install", "react@18.2.0")
        self.check("npm", "install", "react@18.2.0")
        self.assertEqual(self.sent, ["react"])

    def test_osv_unreachable_falls_back_to_the_offline_list(self):
        def down(*a, **k):
            raise OSError("no network")
        si.http_json = down
        blocked, _, notes = self.check("npm", "install", BAD_NPM)
        self.assertEqual(blocked, [BAD_NPM])
        self.assertTrue(any("OSV.dev couldn't be reached" in n for n in notes))

    def test_a_failing_checker_never_blocks(self):
        saved = si.check
        si.check = lambda *a, **k: 1 / 0
        try:
            self.assertEqual(si.main(["npm", "install", "x"]), 0)
        finally:
            si.check = saved

    def test_exit_codes(self):
        cwd = os.getcwd()
        os.chdir(self.dir)
        try:
            self.assertEqual(si.main(["npm", "install", BAD_NPM]), si.BLOCKED)
            self.assertEqual(si.main(["npm", "run", "dev"]), 0)
        finally:
            os.chdir(cwd)


@unittest.skipIf(os.name == "nt" or not shutil.which("bash"), "needs bash")
class ShellFunctions(unittest.TestCase):
    """scanner/shell/safe-install.sh with stand-ins for the checker and the package manager."""

    def run_sh(self, checker_exit, command="npm install x", checker=True):
        tmp = tempfile.mkdtemp(prefix="ardvane-sh-")
        try:
            os.makedirs(os.path.join(tmp, ".checkrepo", "bin"))
            if checker:
                with open(os.path.join(tmp, ".checkrepo", "bin", "safe-install"), "w") as f:
                    f.write(f"#!/bin/sh\nexit {checker_exit}\n")
                os.chmod(os.path.join(tmp, ".checkrepo", "bin", "safe-install"), 0o755)
            fake = os.path.join(tmp, "fakebin")
            os.makedirs(fake)
            with open(os.path.join(fake, "npm"), "w") as f:
                f.write("#!/bin/sh\necho REAL-NPM-RAN \"$@\"\nexit 7\n")
            os.chmod(os.path.join(fake, "npm"), 0o755)
            script = f'. "{os.path.join(SCANNER, "shell", "safe-install.sh")}"; {command}; echo "exit=$?"'
            env = dict(os.environ, HOME=tmp, PATH=fake + os.pathsep + os.environ["PATH"])
            return subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True).stdout
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_blocked_installs_never_run(self):
        out = self.run_sh(10)
        self.assertNotIn("REAL-NPM-RAN", out)
        self.assertIn("exit=1", out)

    def test_allowed_commands_run_with_their_own_exit_code(self):
        out = self.run_sh(0)
        self.assertIn("REAL-NPM-RAN install x", out)
        self.assertIn("exit=7", out)

    def test_a_broken_or_missing_checker_never_breaks_npm(self):
        self.assertIn("REAL-NPM-RAN", self.run_sh(1))                 # e.g. Python crashed
        self.assertIn("REAL-NPM-RAN", self.run_sh(0, checker=False))  # uninstalled: command not found (127)


class OneListOfTools(unittest.TestCase):
    def test_shell_functions_powershell_and_checker_agree(self):
        with open(os.path.join(SCANNER, "shell", "safe-install.sh")) as f:
            sh = set(re.findall(r"^(\w+)\(\)", f.read(), re.M)) - {"__ardvane_safe_install"}
        with open(os.path.join(ROOT, "windows", "install.ps1"), encoding="utf-8") as f:
            ps = set(re.findall(r"'(\w+)'", re.search(r"\$safeTools = (.*)", f.read()).group(1)))
        self.assertEqual(sh, set(si.INSTALLS))
        self.assertEqual(ps, set(si.INSTALLS))


if __name__ == "__main__":
    unittest.main(verbosity=2)
