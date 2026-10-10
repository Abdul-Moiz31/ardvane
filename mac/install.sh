#!/usr/bin/env bash
# Ardvane — installer for macOS (also works on Linux).
#
# Installs:
#   ~/.checkrepo/checkrepo.py        the read-only malware scanner
#   ~/.checkrepo/bin/checkrepo       `checkrepo` command
#   ~/.checkrepo/hooks/*             global git hooks (scan after clone/pull/checkout, block infected pushes)
#   ~/.checkrepo/bin/git-safeclone   safe `git clone` (scans before any project file is written)
# and hardens:
#   npm  -> ignore-scripts=true (packages can't run install scripts)
#   VS Code / Cursor / Windsurf -> automatic tasks off, Workspace Trust on
#
# Usage:  bash install.sh [--dry-run] [--no-npm] [--no-editor] [--no-safeclone] [--force-hooks]
# Re-running is safe. Undo everything with: bash uninstall.sh
#
# --- end of help ---

set -u
KIT="$(cd "$(dirname "$0")/.." && pwd)"   # repository root
SCANNER="$KIT/scanner"
DEST="$HOME/.checkrepo"
DRY=0; NPM=1; EDITOR_HARDEN=1; SAFECLONE=1; FORCE_HOOKS=0
for a in "$@"; do case "$a" in
  --dry-run) DRY=1 ;; --no-npm) NPM=0 ;; --no-editor) EDITOR_HARDEN=0 ;; --no-safeclone) SAFECLONE=0 ;;
  --force-hooks) FORCE_HOOKS=1 ;; -h|--help) sed -n '2,/^# --- end of help/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "unknown option: $a (see --help)"; exit 3 ;; esac; done

G=$'\033[1;32m'; Y=$'\033[1;33m'; R=$'\033[1;31m'; X=$'\033[0m'
ok()   { echo "${G}✔${X} $*"; }
warn() { echo "${Y}!${X} $*"; }
die()  { echo "${R}✘ $*${X}"; exit 1; }
# run a command (or just print it in --dry-run). Arguments are passed as-is — no eval, so any path is safe.
run()  { if [ $DRY -eq 1 ]; then echo "  [dry-run] $*"; else "$@" || die "failed: $*"; fi; }
backup() { [ -f "$1" ] && [ ! -f "$1.bak-checkrepo" ] && cp "$1" "$1.bak-checkrepo"; return 0; }   # keep the FIRST original
BEGIN="# >>> polinrider-survival-kit >>>"; END="# <<< polinrider-survival-kit <<<"

echo "Ardvane installer$([ $DRY -eq 1 ] && echo ' (dry run — nothing will change)')"
echo

# ---------------------------------------------------------------- prerequisites
if [ "$(uname)" = "Darwin" ]; then HINT="install them with: xcode-select --install"; else HINT="install them with your package manager (e.g. sudo apt install git python3)"; fi
command -v git >/dev/null || die "git is not installed — $HINT"
PY=""
for c in python3 python; do
  command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1 && { PY="$(command -v "$c")"; break; }
done
[ -n "$PY" ] || die "Python 3.8+ is required — $HINT"
ok "git and $("$PY" --version 2>&1) found"

# ---------------------------------------------------------------- files
run mkdir -p "$DEST/bin" "$DEST/hooks"
run cp "$SCANNER/checkrepo.py" "$DEST/checkrepo.py"
run cp "$SCANNER/hooks/dispatch" "$DEST/hooks/dispatch"
run chmod 755 "$DEST/hooks/dispatch"
run cp "$SCANNER/safeclone/git-safeclone" "$DEST/bin/git-safeclone"
for f in kitlib.py github_check.py autofix.py; do run cp "$SCANNER/$f" "$DEST/$f"; done   # shared helpers, GitHub check, fixer
run cp "$SCANNER/lists/malware-paths.txt" "$DEST/malware-paths.txt"
run chmod 755 "$DEST/bin/git-safeclone"
if [ $DRY -eq 1 ]; then echo "  [dry-run] create ~/.checkrepo/bin/checkrepo"; else
  printf '#!/bin/sh\nexec "%s" "%s" "$@"\n' "$PY" "$DEST/checkrepo.py" > "$DEST/bin/checkrepo" && chmod 755 "$DEST/bin/checkrepo" || die "could not create the checkrepo command"
fi
for h in applypatch-msg pre-applypatch post-applypatch pre-commit pre-merge-commit prepare-commit-msg commit-msg \
         post-commit pre-rebase post-checkout post-merge pre-push pre-receive update proc-receive post-receive \
         post-update push-to-checkout pre-auto-gc post-rewrite sendemail-validate; do
  run ln -sf dispatch "$DEST/hooks/$h"
done
ok "scanner installed in ~/.checkrepo"

# ---------------------------------------------------------------- global git hooks
current="$(git config --global --get core.hooksPath || true)"
if [ -z "$current" ] || [ "$current" = "$DEST/hooks" ] || [ $FORCE_HOOKS -eq 1 ]; then
  if [ -n "$current" ] && [ "$current" != "$DEST/hooks" ] && [ $DRY -eq 0 ]; then
    echo "$current" > "$DEST/previous-hooksPath"   # restored by uninstall.sh
  fi
  run git config --global core.hooksPath "$DEST/hooks"
  [ $DRY -eq 1 ] || touch "$DEST/hooks-enabled"     # tells the daily check that hooks are expected to be on
  ok "git hooks on: scan after clone/pull/checkout, block infected pushes"
else
  [ $DRY -eq 1 ] || rm -f "$DEST/hooks-enabled"
  warn "you already use a global hooks folder: $current — not changed."
  warn "  Either re-run with --force-hooks (your old setting is saved and restored on uninstall),"
  warn "  or call the kit from each of your hooks, e.g. in your pre-push hook:  ~/.checkrepo/hooks/pre-push \"\$@\" || exit 1"
fi

# ---------------------------------------------------------------- shell setup (PATH + safe clone)
block="$BEGIN
export PATH=\"\$HOME/.checkrepo/bin:\$PATH\""
if [ $SAFECLONE -eq 1 ]; then
  block="$block
# safe clone: scans before writing project files (bypass once with: command git clone ...)
function git { if [ \"\$1\" = \"clone\" ]; then shift; git-safeclone \"\$@\"; else command git \"\$@\"; fi; }"
fi
block="$block
$END"
rcs=()
for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile"; do [ -f "$rc" ] && rcs+=("$rc"); done
if [ ${#rcs[@]} -eq 0 ]; then   # no rc file yet: create the one for the user's shell
  case "$(basename "${SHELL:-}")" in zsh) rcs=("$HOME/.zshrc") ;; *) rcs=("$HOME/.bash_profile") ;; esac
fi
for rc in "${rcs[@]}"; do
  if [ $DRY -eq 1 ]; then echo "  [dry-run] update $rc"; continue; fi
  backup "$rc"
  "$PY" - "$rc" "$BEGIN" "$END" "$block" <<'PYEOF' || die "could not update $rc"
import sys, re, os
rc, begin, end, block = sys.argv[1:5]
s = open(rc).read() if os.path.exists(rc) else ""
s = re.sub(re.escape(begin) + r".*?" + re.escape(end) + r"\n?", "", s, flags=re.S)
open(rc, "w").write(s.rstrip("\n") + ("\n\n" if s.strip() else "") + block + "\n")
PYEOF
  ok "updated ${rc/#$HOME/~} (original kept as $(basename "$rc").bak-checkrepo)"
done

# ---------------------------------------------------------------- npm
if [ $NPM -eq 1 ] && command -v npm >/dev/null; then
  run npm config set ignore-scripts true
  ok "npm: install scripts blocked (per trusted project if needed: npm install --ignore-scripts=false)"
elif [ $NPM -eq 1 ]; then
  warn "npm not found — skipped"
fi

# ---------------------------------------------------------------- editors
if [ $EDITOR_HARDEN -eq 1 ]; then
  for f in "$HOME/Library/Application Support/Code/User/settings.json" "$HOME/Library/Application Support/Cursor/User/settings.json" \
           "$HOME/Library/Application Support/Windsurf/User/settings.json" "$HOME/.config/Code/User/settings.json" \
           "$HOME/.config/Cursor/User/settings.json"; do
    [ -d "$(dirname "$f")" ] || continue
    if [ $DRY -eq 1 ]; then echo "  [dry-run] harden $f"; continue; fi
    backup "$f"
    if "$PY" - "$f" <<'PYEOF'
import json, os, sys
f = sys.argv[1]
s = open(f, encoding="utf-8").read() if os.path.exists(f) else "{}"
try:
    d = json.loads(s or "{}")
except ValueError:
    sys.exit(2)          # file has comments/trailing commas: don't risk rewriting it
d["task.allowAutomaticTasks"] = "off"
d["security.workspace.trust.enabled"] = True
d["security.workspace.trust.startupPrompt"] = "always"
d["security.workspace.trust.untrustedFiles"] = "prompt"
open(f, "w", encoding="utf-8").write(json.dumps(d, indent=4, ensure_ascii=False) + "\n")
PYEOF
    then ok "editor hardened: ${f/#$HOME/~}"
    else warn "could not safely edit ${f/#$HOME/~} (it contains comments). Add these four settings by hand:"
         echo '      "task.allowAutomaticTasks": "off",'
         echo '      "security.workspace.trust.enabled": true,'
         echo '      "security.workspace.trust.startupPrompt": "always",'
         echo '      "security.workspace.trust.untrustedFiles": "prompt"'
    fi
  done
fi

# ---------------------------------------------------------------- self-test
echo
if [ $DRY -eq 0 ] && [ -f "$SCANNER/tests/run_tests.py" ]; then
  if CHECKREPO="$DEST/checkrepo.py" "$PY" "$SCANNER/tests/run_tests.py" --quiet; then ok "self-test passed"; else warn "self-test reported problems — see above"; fi
fi
echo
echo "${G}Done.${X} Open a NEW terminal window, then try:  checkrepo --version"
echo "Scan any folder before opening it:  checkrepo ~/Downloads/some-project"
echo "Optional daily check: bash $KIT/mac/install-routine.sh"
echo "Notes: 'gh repo clone' and GUI clone buttons bypass safe clone (the post-clone hook still warns);"
echo "       tools that install their own git hooks (pre-commit, Git LFS) won't while a global hooks folder is set — see docs/checkrepo.md"
