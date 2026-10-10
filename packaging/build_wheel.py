#!/usr/bin/env python3
"""Build the Ardvane wheel for PyPI: dist/ardvane-<version>-py3-none-any.whl

    python3 packaging/build_wheel.py

Standard library only (no setuptools / build / twine), and reproducible: files are sorted and every timestamp is fixed,
so the same source always gives the same wheel. The package is `ardvane/` = packaging/ardvane/*.py plus the kit's files
(app, scanner, mac, windows, docs, scan scripts) exactly as they are in the repository.
"""
import base64
import hashlib
import os
import re
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGE = "ardvane"
KIT_PARTS = ["app", "scanner", "mac", "windows", "docs", "scan-my-machine.sh", "scan-my-machine.ps1",
             "LICENSE", "README.md", "CHANGELOG.md"]
SKIP = re.compile(r"(^|/)(__pycache__|\.DS_Store|.*\.pyc)(/|$)")
EXECUTABLE = re.compile(r"(\.sh$|/dispatch$|/git-safeclone$)")
FIXED_TIME = (2020, 1, 1, 0, 0, 0)
SUMMARY = "Protects developers from malware that spreads through code: scan, block, fix and check daily. Runs only on your computer."


def version():
    with open(os.path.join(ROOT, "app", "backend", "config.py"), encoding="utf-8") as f:
        return re.search(r'^VERSION = "(\d+\.\d+\.\d+)"$', f.read(), re.M).group(1)


def kit_files():
    """(path inside the wheel, path on disk) for every file, sorted."""
    files = [(f"{PACKAGE}/{n}", os.path.join(ROOT, "packaging", PACKAGE, n)) for n in ("__init__.py", "__main__.py")]
    for part in KIT_PARTS:
        full = os.path.join(ROOT, part)
        if os.path.isfile(full):
            files.append((f"{PACKAGE}/{part}", full))
            continue
        for dp, dns, fns in os.walk(full):
            for fn in fns:
                rel = os.path.relpath(os.path.join(dp, fn), ROOT).replace(os.sep, "/")
                if not SKIP.search(rel):
                    files.append((f"{PACKAGE}/{rel}", os.path.join(dp, fn)))
    return sorted(files)


def metadata(ver):
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
        readme = f.read()
    head = [("Metadata-Version", "2.1"), ("Name", PACKAGE), ("Version", ver), ("Summary", SUMMARY),
            ("Home-page", "https://github.com/Abdul-Moiz31/ardvane"), ("Author", "Abdul Moiz"), ("License", "MIT"),
            ("Project-URL", "Source, https://github.com/Abdul-Moiz31/ardvane"),
            ("Project-URL", "Changelog, https://github.com/Abdul-Moiz31/ardvane/blob/main/CHANGELOG.md"),
            ("Project-URL", "Issues, https://github.com/Abdul-Moiz31/ardvane/issues"),
            ("Keywords", "security,malware,git,supply-chain,developer-tools"),
            ("Classifier", "License :: OSI Approved :: MIT License"),
            ("Classifier", "Programming Language :: Python :: 3"),
            ("Classifier", "Operating System :: MacOS"), ("Classifier", "Operating System :: POSIX :: Linux"),
            ("Classifier", "Operating System :: Microsoft :: Windows"),
            ("Classifier", "Topic :: Security"), ("Classifier", "Environment :: Console"),
            ("Requires-Python", ">=3.8"), ("Description-Content-Type", "text/markdown")]
    return "".join(f"{k}: {v}\n" for k, v in head) + "\n" + readme


def record_line(name, data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{name},sha256={digest},{len(data)}"


def build(out_dir=None):
    ver = version()
    out_dir = out_dir or os.path.join(ROOT, "dist")
    os.makedirs(out_dir, exist_ok=True)
    wheel = os.path.join(out_dir, f"{PACKAGE}-{ver}-py3-none-any.whl")
    info = f"{PACKAGE}-{ver}.dist-info"
    generated = [
        (f"{info}/METADATA", metadata(ver).encode()),
        (f"{info}/WHEEL", b"Wheel-Version: 1.0\nGenerator: ardvane build_wheel.py\nRoot-Is-Purelib: true\nTag: py3-none-any\n"),
        (f"{info}/entry_points.txt", f"[console_scripts]\n{PACKAGE} = {PACKAGE}.__main__:main\n".encode()),
        (f"{info}/licenses/LICENSE", open(os.path.join(ROOT, "LICENSE"), "rb").read()),
    ]
    records = []

    def add(zf, name, data, executable=False):
        zi = zipfile.ZipInfo(name, FIXED_TIME)
        zi.compress_type = zipfile.ZIP_DEFLATED
        zi.external_attr = ((0o100755 if executable else 0o100644) & 0xFFFF) << 16
        zf.writestr(zi, data)
        records.append(record_line(name, data))

    with zipfile.ZipFile(wheel, "w") as zf:
        for name, path in kit_files():
            with open(path, "rb") as f:
                add(zf, name, f.read(), bool(EXECUTABLE.search(name)))
        for name, data in generated:
            add(zf, name, data)
        record_name = f"{info}/RECORD"
        zi = zipfile.ZipInfo(record_name, FIXED_TIME)
        zi.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(zi, "\n".join(records + [f"{record_name},,"]) + "\n")
    return wheel


if __name__ == "__main__":
    path = build(sys.argv[1] if len(sys.argv) > 1 else None)
    print(f"built {os.path.relpath(path, ROOT)} ({os.path.getsize(path) // 1024} KB)")
