"""The kit's own guides (docs/*.md), served read-only to the Learn page."""
import os

from .config import KIT

GROUPS = [("If you're infected", "after-a-scan"), ("The attacks", "attacks"), ("The story", "story"), ("Reference", "")]
ROOT = os.path.join(KIT, "docs")


def _title(full, fallback):
    try:
        with open(full, encoding="utf-8") as f:
            for line in f:
                if line.startswith("# "):
                    return line[2:].strip()
    except OSError:
        pass
    return fallback


def list_all():
    out = []
    for group, sub in GROUPS:
        folder = os.path.join(ROOT, sub)
        try:
            names = sorted(n for n in os.listdir(folder) if n.endswith(".md"))
        except OSError:
            continue
        names = (["README.md"] if "README.md" in names else []) + [n for n in names if n != "README.md"]
        for name in names:
            rel = f"{sub}/{name}" if sub else name
            out.append({"group": group, "path": rel, "title": _title(os.path.join(folder, name), name[:-3].replace("-", " ").capitalize())})
    return out


def read(rel):
    """Text of a guide, or None. Only paths from list_all() are accepted, so nothing outside docs/ can be read."""
    if rel not in {d["path"] for d in list_all()}:
        return None
    with open(os.path.join(ROOT, *rel.split("/")), encoding="utf-8") as f:
        return f.read()
