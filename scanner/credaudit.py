#!/usr/bin/env python3
"""credaudit — find credentials sitting in plain text files on this computer, and say how to move off them.

Part of Ardvane (MIT License). Python 3.8+, no dependencies. Read-only.

Stealers and worms (PolinRider, Shai-Hulud, the npm and PyPI stealers) go straight for the same few files: AWS keys,
npm tokens, GitHub CLI tokens, Docker logins, git passwords. A credential kept in the system keychain, or a short-lived
login (AWS SSO), is far harder to take and worthless a few hours later.

  credaudit.py [--json]

It looks only at well-known credential files in your home folder. It never prints, copies or sends a secret: it says
which file holds one, how many, how long ago the file last changed, and what to do. For AWS it shows the last 4
characters of the access key ID (an identifier, not a secret) so you can find the key in the AWS console.
Ardvane does not edit these files; the steps are yours to run, in order.

Exit code: 0 nothing in plain text, 2 something found.
"""
import json
import os
import re
import stat
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kitlib import HOME, IS_MAC, IS_WIN, safe_output  # noqa: E402

OLD_DAYS = 90


def keystore():
    return "the macOS keychain" if IS_MAC else "the Windows Credential Manager" if IS_WIN else "your system keyring"


def helper():
    return "osxkeychain" if IS_MAC else "manager" if IS_WIN else "libsecret"


def read(path, limit=1_000_000):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return None


def facts(path):
    """(age in days, readable by other users?) of a file, or (None, False)."""
    try:
        st = os.stat(path)
    except OSError:
        return None, False
    return max(0, int((time.time() - st.st_mtime) // 86400)), bool(st.st_mode & (stat.S_IRGRP | stat.S_IROTH)) and not IS_WIN


def tidy(path):
    return "~" + path[len(HOME):] if path.startswith(HOME) else path


def item(id_, title, path, summary, why, steps, links=(), count=1, detail=None):
    age, shared = facts(path)
    return {"id": id_, "title": title, "path": tidy(path), "summary": summary, "why": why, "steps": list(steps),
            "links": [list(l) for l in links], "count": count, "age_days": age, "old": age is not None and age > OLD_DAYS,
            "readable_by_others": shared, "detail": detail or []}


def aws(home):
    path = os.path.join(home, ".aws", "credentials")
    text = read(path)
    if not text:
        return None
    profiles, cur = [], None
    for line in text.splitlines():
        m = re.match(r"^\s*\[([^\]]+)\]", line)
        if m:
            cur = {"name": m.group(1).strip(), "id": "", "secret": False}
            profiles.append(cur)
        elif cur is not None:
            k, _, v = line.partition("=")
            k, v = k.strip().lower(), v.strip()
            if k == "aws_access_key_id":
                cur["id"] = v
            elif k == "aws_secret_access_key" and v:
                cur["secret"] = True
    keys = [p for p in profiles if p["secret"]]
    if not keys:
        return None
    config = read(os.path.join(home, ".aws", "config")) or ""
    sso = bool(re.search(r"^\s*(sso_session|sso_start_url)\s*=", config, re.M))
    names = ", ".join(p["name"] for p in keys)
    detail = [f"profile \"{p['name']}\"" + (f": access key ID ending {p['id'][-4:]}" if len(p["id"]) >= 8 else "") for p in keys]
    p0 = keys[0]["name"]
    steps = ([] if sso else ["Run `aws configure sso` and sign in. It stores a login that expires in hours, not a key that never does."]) + [
        f"Check the new login works: `aws sts get-caller-identity --profile <your sso profile>`.",
        "In the AWS console open IAM → Users → your user → Security credentials. Find the access key (ID ending shown above) and choose "
        "Actions → Deactivate, wait a day to see nothing breaks, then Delete.",
        f"Remove the [{p0}] section" + (" (and the other profiles that have keys)" if len(keys) > 1 else "") + " from ~/.aws/credentials, or delete the file.",
        "If this computer was ever infected, the key may already be copied: deactivate it first, then look at CloudTrail for use you don't recognise."]
    return item("aws", "AWS access keys in a plain file", path,
                f"{len(keys)} profile{'s' if len(keys) != 1 else ''} with a long-lived secret key ({names})" + ("; SSO is already set up, so the keys can go" if sso else ""),
                "A key in this file works from anywhere, forever, until someone deletes it. Stealers copy this exact file first.", steps,
                [("AWS: set up SSO", "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html")], len(keys), detail)


def github_cli(home):
    path = os.path.join(home, ".config", "gh", "hosts.yml")
    if IS_WIN:
        path = os.path.join(os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming"), "GitHub CLI", "hosts.yml")
    text = read(path)
    if not text or not re.search(r"^\s*oauth_token:\s*\S+", text, re.M):
        return None
    return item("github-cli", "GitHub CLI token in a plain file", path, "the GitHub CLI stored its login in plain text instead of in " + keystore(),
                "The token can read and push to every repository you can. It is what the worm uses to force-push into all of them.",
                ["Run `gh auth logout`, then `gh auth login`. Current versions of gh use " + keystore() + " by default.",
                 "Check the file no longer holds `oauth_token`.",
                 "Revoke the old token at github.com/settings/applications (GitHub CLI) so the copy in the file stops working."],
                [("GitHub: authorized apps", "https://github.com/settings/applications")])


def npm(home):
    path = os.path.join(home, ".npmrc")
    text = read(path)
    if not text:
        return None
    hits = [l for l in text.splitlines() if re.search(r"(_authToken|_auth|_password)\s*=\s*(?!\$\{)\S+", l) and not l.lstrip().startswith(("#", ";"))]
    if not hits:
        return None
    return item("npm", "npm token in a plain file", path, f"{len(hits)} publish token{'s' if len(hits) != 1 else ''} in ~/.npmrc",
                "Anyone with the token can publish new versions of your packages. Worms use it to push themselves into every package you own.",
                ["Go to npmjs.com → your avatar → Access Tokens, and delete this token.",
                 "Make a new granular token that expires in 30 days or less, limited to the packages and the read/write you need, and use it from an environment variable "
                 "(`//registry.npmjs.org/:_authToken=${NPM_TOKEN}` in ~/.npmrc) instead of writing it in the file.",
                 "For CI, use npm trusted publishing (no token at all) instead of a stored one.",
                 "Remove the line from ~/.npmrc."],
                [("npm: trusted publishing", "https://docs.npmjs.com/trusted-publishers")], len(hits))


def docker(home):
    path = os.path.join(home, ".docker", "config.json")
    text = read(path)
    if not text:
        return None
    try:
        cfg = json.loads(text)
    except ValueError:
        return None
    stored = [r for r, v in (cfg.get("auths") or {}).items() if isinstance(v, dict) and v.get("auth")
              and not cfg.get("credsStore") and r not in (cfg.get("credHelpers") or {})]
    if not stored:
        return None
    return item("docker", "Docker logins in a plain file", path, f"{len(stored)} registry login{'s' if len(stored) != 1 else ''} stored as base64 text (not encrypted)",
                "Base64 is not encryption: anyone who copies the file has the password for " + ", ".join(stored[:3]) + ".",
                [f"Set the credentials store: in ~/.docker/config.json add `\"credsStore\": \"{('osxkeychain' if IS_MAC else 'wincred' if IS_WIN else 'secretservice')}\"`.",
                 "Run `docker logout <registry>` for each registry, then `docker login <registry>` so the new login goes into " + keystore() + ".",
                 "Use an access token, not your account password, and revoke the old one in the registry's settings."],
                [("Docker: credential stores", "https://docs.docker.com/reference/cli/docker/login/#credential-stores")], len(stored), [r for r in stored[:10]])


def git_credentials(home):
    path = os.path.join(home, ".git-credentials")
    text = read(path)
    if not text or not text.strip():
        return None
    n = len([l for l in text.splitlines() if "://" in l])
    if not n:
        return None
    return item("git-credentials", "Git passwords in a plain file", path, f"{n} saved git login{'s' if n != 1 else ''} with the password or token in the file",
                "Each line is a full address with its password. It is the first file a stealer reads after your SSH keys.",
                [f"Run `git config --global credential.helper {helper()}` so git keeps logins in " + keystore() + ".",
                 "Revoke the tokens in the file at the service that issued them (for GitHub: github.com/settings/tokens).",
                 "Delete ~/.git-credentials. Git asks once more, then remembers in the keychain."],
                [("GitHub: personal access tokens", "https://github.com/settings/tokens")], n)


def netrc(home):
    for name in (".netrc", "_netrc"):
        path = os.path.join(home, name)
        text = read(path)
        if text and re.search(r"\bpassword\s+\S+", text):
            n = len(re.findall(r"\bmachine\s+\S+", text))
            return item("netrc", "Passwords in ~/.netrc", path, f"{n or 1} login{'s' if n != 1 else ''} with the password in plain text",
                        "curl, git and many tools read this file, and so do stealers.",
                        ["Revoke each password or token at the service that issued it.",
                         "Delete the file, or replace each entry by a credential helper or an environment variable.",
                         "Keep it at mode 600 (`chmod 600 ~/.netrc`) if you must keep it."], count=n or 1)
    return None


def pypi(home):
    path = os.path.join(home, ".pypirc")
    text = read(path)
    if not text or not re.search(r"^\s*password\s*[:=]\s*\S+", text, re.M):
        return None
    return item("pypi", "PyPI token in a plain file", path, "an upload token in ~/.pypirc",
                "Anyone with it can publish new versions of your packages.",
                ["Delete the token at pypi.org → Account settings → API tokens.",
                 "Use PyPI trusted publishing for releases (no stored token) or `keyring` with twine.",
                 "Remove the password line from ~/.pypirc."], [("PyPI: trusted publishers", "https://docs.pypi.org/trusted-publishers/")])


def kube(home):
    path = os.path.join(home, ".kube", "config")
    text = read(path)
    if not text or not re.search(r"^\s*token:\s*\S+", text, re.M):
        return None
    return item("kube", "Kubernetes token in a plain file", path, "a static cluster token in ~/.kube/config",
                "A static token does not expire. Anyone who copies the file controls that cluster as you.",
                ["Switch the cluster to a short-lived login (your cloud's `get-credentials`, or an exec plugin like `aws eks get-token`).",
                 "Rotate the token in the cluster, then remove the `token:` line from the file."])


def gcloud(home):
    path = os.path.join(home, ".config", "gcloud", "application_default_credentials.json")
    text = read(path)
    if not text or '"refresh_token"' not in text and '"private_key"' not in text:
        return None
    return item("gcloud", "Google Cloud login file", path, "application default credentials with a long-lived refresh token or key",
                "The file works from any computer until you revoke it.",
                ["Run `gcloud auth application-default revoke` to cancel it.",
                 "Use `gcloud auth application-default login` only when you need it, or workload identity in CI.",
                 "If it held a service-account key (\"private_key\"), delete that key in the console (IAM → Service accounts → Keys)."])


CHECKS = (aws, github_cli, npm, docker, git_credentials, netrc, pypi, kube, gcloud)


def audit(home=None):
    """{items: [...], checked: n, home: ...}. `home` is for tests."""
    home = home or HOME
    items = []
    for check in CHECKS:
        try:
            found = check(home)
        except Exception:                              # one unreadable file must not hide the rest
            found = None
        if found:
            items.append(found)
    items.sort(key=lambda i: (not i["old"], i["id"]))
    return {"items": items, "checked": len(CHECKS), "old_days": OLD_DAYS}


def main(argv):
    safe_output()
    if argv[:1] in (["-h"], ["--help"]):
        print(__doc__)
        return 0
    res = audit()
    if "--json" in argv:
        print(json.dumps(res))
        return 2 if res["items"] else 0
    if not res["items"]:
        print(f"Nothing in plain text: checked {res['checked']} well-known credential files.")
        return 0
    for it in res["items"]:
        age = f", file last changed {it['age_days']} days ago" if it["age_days"] is not None else ""
        print(f"\n⚠️  {it['title']}\n   {it['path']}{age}\n   {it['summary']}")
        for d in it["detail"]:
            print(f"     - {d}")
        print(f"   Why it matters: {it['why']}\n   What to do:")
        for i, step in enumerate(it["steps"], 1):
            print(f"     {i}. {step}")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
