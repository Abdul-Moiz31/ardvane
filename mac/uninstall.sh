#!/usr/bin/env bash
# polinrider-survival-kit — uninstaller for macOS / Linux. Reverses install.sh and install-routine.sh.
# Leaves npm's ignore-scripts and your editor settings as they are (they are good defaults);
# the commands to revert them are printed at the end.

DEST="$HOME/.checkrepo"
BEGIN="# >>> polinrider-survival-kit >>>"; END="# <<< polinrider-survival-kit <<<"
PY="$(command -v python3 || command -v python)"
LABEL="com.polinrider-survival-kit.daily-check"; PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

# 1. daily routine
if [ -f "$PLIST" ]; then
  launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null
  rm -f "$PLIST" && echo "✔ daily check removed"
fi

# 2. git hooks (restore a previous global hooks folder if the installer replaced one)
if [ "$(git config --global --get core.hooksPath)" = "$DEST/hooks" ]; then
  if [ -s "$DEST/previous-hooksPath" ]; then
    git config --global core.hooksPath "$(cat "$DEST/previous-hooksPath")" && echo "✔ restored your previous git hooks folder: $(cat "$DEST/previous-hooksPath")"
  else
    git config --global --unset core.hooksPath && echo "✔ global git hooks removed"
  fi
fi

# 3. shell files
for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile"; do
  [ -f "$rc" ] || continue
  "$PY" - "$rc" "$BEGIN" "$END" <<'PYEOF'
import sys, re
rc, begin, end = sys.argv[1:4]
s = open(rc).read()
n = re.sub(r"\n*" + re.escape(begin) + r".*?" + re.escape(end) + r"\n?", "\n", s, flags=re.S)
if n != s:
    open(rc, "w").write(n)
    print("✔ cleaned", rc)
PYEOF
done

# 4. files (reports and quarantined downloads are kept so you can review them)
if [ -d "$DEST" ]; then
  rm -rf "$DEST/bin" "$DEST/hooks" "$DEST/checkrepo.py" "$DEST/github_check.py" "$DEST/github-seen.json" "$DEST/daily-check.sh" "$DEST/fingerprints.txt" \
         "$DEST/hooks-enabled" "$DEST/previous-hooksPath"
  rmdir "$DEST" 2>/dev/null
  if [ -d "$DEST" ]; then
    echo "✔ removed the kit; kept in ~/.checkrepo for you to review or delete:"
    for k in "$DEST"/*; do [ -e "$k" ] && echo "    ${k/#$HOME/~}"; done
  else
    echo "✔ removed ~/.checkrepo"
  fi
fi
[ -d "$HOME/.config/checkrepo" ] && echo "  (your allowlist in ~/.config/checkrepo was kept)"
echo
echo "Kept on purpose (good defaults). To revert them too:"
echo "  npm config delete ignore-scripts"
echo "  remove \"task.allowAutomaticTasks\" / \"security.workspace.trust.*\" from your editor settings.json"
echo "  (the original files are saved next to them as settings.json.bak-checkrepo)"
echo "Open a new terminal window for the change to take effect."
