#!/usr/bin/env python3
"""sandbox — open a coding test or an unknown repository inside a throwaway container, not on your computer.

Part of Ardvane (MIT License). Python 3.8+, no dependencies. Needs Docker or Podman.

  sandbox.py TARGET [--image IMAGE] [--no-network] [--force] [--dry-run]

TARGET is owner/name (or a github.com link), or a folder on this computer.

What happens:
  1. The repository is scanned first, read-only: a GitHub repository on every branch without cloning it, a folder with
     the usual folder scan. If malware is found, nothing is opened (--force overrides, for people who study malware).
  2. A container starts with no folder of yours mounted, no environment variables of yours, no Docker socket, all Linux
     capabilities dropped (except taking ownership of a copied folder), no new privileges, and limited memory, CPU and processes.
  3. The code goes in: a GitHub repository is cloned INSIDE the container (hooks off, shallow, no submodules); a folder
     is copied in. You get a shell in it. Run the test there.
  4. When you leave the shell, the container and everything in it is deleted.

--no-network cuts the container off from the network (folders only: a clone needs it). Without it, `npm install` works.

What this protects: your files, keys, browser, ~/.ssh and the rest of your computer from anything the code runs.
What it does not: a determined exploit of the container runtime itself (rare, and why you should keep it updated), and
anything you copy out of the container yourself, or secrets you type into it. Don't log in to anything in there.
Exit code: 0 done, 1 refused because malware was found, 3 not possible (no runtime, bad input).
"""
import os
import re
import secrets
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kitlib import safe_output  # noqa: E402
import github_check as gc  # noqa: E402

DEFAULT_IMAGE = "node:22-bookworm"           # git, Node, Python and a compiler: what take-home tests usually need
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,80}(?::[A-Za-z0-9._-]{1,60})?$")
LIMITS = ["--memory", "4g", "--cpus", "2", "--pids-limit", "512"]
LOCKDOWN = ["--cap-drop", "ALL", "--cap-add", "CHOWN", "--security-opt", "no-new-privileges", "--init"]   # CHOWN only: to own the copied files
WORKDIR = "/work"
CLONE = 'git -c core.hooksPath=/dev/null clone --depth 1 --no-recurse-submodules -- "$1" repo'


def runtime():
    """('docker' | 'podman' | None, ready?, message). Ready means the engine answers, not just that the program exists."""
    for exe in ("docker", "podman"):
        path = shutil.which(exe)
        if not path:
            continue
        try:
            r = subprocess.run([path, "info"], capture_output=True, timeout=20, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            return exe, False, f"{exe} is installed but did not answer"
        if r.returncode == 0:
            return exe, True, ""
        return exe, False, f"{exe} is installed but not running: start it (Docker Desktop, OrbStack or Colima), then try again"
    return None, False, ("needs Docker or Podman, and found neither. Install one (Docker Desktop, OrbStack, Colima or Podman), "
                         "start it, then run this again")


def parse_target(text):
    """('github', 'owner/name') or ('folder', absolute path). Raises ValueError with a message for the user."""
    raw = str(text).strip()
    if not raw:
        raise ValueError("say what to open: owner/name, a github.com link, or a folder")
    expanded = os.path.abspath(os.path.expanduser(raw))
    looks_local = raw in (".", "..") or raw.startswith(("/", "~", "./", "../", ".\\", "..\\")) or re.match(r"^[A-Za-z]:[\\/]", raw)
    if looks_local:
        if not os.path.isdir(expanded):
            raise ValueError(f"'{raw}' is not a folder that exists")
        return "folder", expanded
    try:
        return "github", gc.parse_repo(raw)
    except ValueError:
        if os.path.isdir(expanded):
            return "folder", expanded
        raise ValueError(f"'{raw}' is neither a GitHub repository (owner/name or its github.com link) nor a folder that exists")


def container_name():
    return "ardvane-sandbox-" + secrets.token_hex(4)


def commands(exe, kind, target, name, image=DEFAULT_IMAGE, network=True):
    """Every command the sandbox runs, as lists, in order: [(what, argv)]. The target is only ever passed as an
    argument (never joined into a shell string), and nothing of the host is mounted or passed through."""
    if not IMAGE_RE.fullmatch(image):
        raise ValueError(f"'{image}' is not a valid image name")
    run = [exe, "run", "-d", "--rm", "--name", name, *LOCKDOWN, *LIMITS, "-w", WORKDIR,
           "--network", "bridge" if network else "none", image, "sleep", "infinity"]
    steps = [("start the container", run)]
    if kind == "github":
        steps.append(("clone it inside the container", [exe, "exec", "-w", WORKDIR, name, "bash", "-c", CLONE, "_",
                                                         f"https://github.com/{target}.git"]))
    else:
        steps.append(("copy the folder in", [exe, "cp", target + os.sep + ".", f"{name}:{WORKDIR}/repo"]))
        steps.append(("take ownership of the copy", [exe, "exec", name, "chown", "-R", "0:0", f"{WORKDIR}/repo"]))   # copied files keep your user id: the container's root couldn't write to them
    steps.append(("open a shell", [exe, "exec", "-it", "-w", f"{WORKDIR}/repo", name, "bash"]))
    steps.append(("delete the container", [exe, "rm", "-f", name]))
    return steps


def precheck(kind, target):
    """Scan before opening. Returns (ok, message): not ok when malware is found."""
    if kind == "github":
        code = subprocess.call([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "github_check.py"),
                                "--repo", target, "--rescan"])
        label = f"GitHub repository {target}"
    else:
        code = subprocess.call([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "checkrepo.py"), target])
        label = f"folder {target}"
    if code == 1:
        return False, f"{label} contains malware: not opened"
    if code == 3:
        return False, f"{label} could not be checked: not opened (use --force to open it anyway)"
    return True, ""


def open_sandbox(target, image=DEFAULT_IMAGE, network=True, force=False, dry_run=False):
    """Run the whole flow. Returns an exit code."""
    kind, spec = parse_target(target)
    if kind == "github" and not network:
        raise ValueError("--no-network works for folders only: cloning needs the network")
    exe, ready, why = runtime()
    name = container_name()
    steps = commands(exe or "docker", kind, spec, name, image, network)
    if dry_run:
        for what, argv in steps:
            print(f"{what}: " + " ".join(argv))
        return 0
    if not ready:
        print(f"sandbox: {why}", file=sys.stderr)
        return 3
    ok, message = precheck(kind, spec)
    if not ok and not force:
        print(f"sandbox: {message}", file=sys.stderr)
        return 1
    print(f"Opening {spec} in a throwaway container ({image}). Nothing of your computer is shared with it.")
    code = 0
    try:
        for what, argv in steps[:-1]:
            quiet = what in ("start the container", "copy the folder in", "take ownership of the copy")
            r = subprocess.call(argv, stdout=subprocess.DEVNULL if quiet else None)
            if r != 0 and what != "open a shell":      # leaving the shell with a non-zero code is not a failure
                print(f"sandbox: could not {what}", file=sys.stderr)
                code = 3
                break
        if code == 0:
            print("\nLeft the sandbox. Deleting the container and everything in it.")
    except KeyboardInterrupt:
        code = 130
    finally:
        subprocess.call(steps[-1][1], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return code


def main(argv):
    safe_output()
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 3
    image, args, flags, it = DEFAULT_IMAGE, [], set(), iter(argv)
    for a in it:
        if a == "--image":
            image = next(it, "")
        elif a.startswith("--"):
            flags.add(a)
        else:
            args.append(a)
    if len(args) != 1:
        print("sandbox: give exactly one repository (owner/name) or folder", file=sys.stderr)
        return 3
    try:
        return open_sandbox(args[0], image, "--no-network" not in flags, "--force" in flags, "--dry-run" in flags)
    except ValueError as e:
        print(f"sandbox: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
