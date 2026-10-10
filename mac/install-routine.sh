#!/usr/bin/env bash
# Ardvane — schedule the daily check on macOS with launchd (runs every day at 09:00;
# if the Mac was asleep at that time it runs when it wakes — not if it was switched off). Also records
# fingerprints of the kit's files so the check can tell you if malware tampers with them.
#   bash install-routine.sh [HH:MM]        e.g.  bash install-routine.sh 8:30   (or: 8 30)
#   bash install-routine.sh --remove

set -u
DEST="$HOME/.checkrepo"; LABEL="com.polinrider-survival-kit.daily-check"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ "${1:-}" = "--remove" ]; then
  launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null; rm -f "$PLIST"; echo "✔ daily check removed"; exit 0
fi
if [[ "${1:-}" == *:* ]]; then H="${1%%:*}"; M="${1#*:}"; else H="${1:-9}"; M="${2:-0}"; fi
H="${H#0}"; M="${M#0}"; H="${H:-0}"; M="${M:-0}"
if ! [[ "$H" =~ ^[0-9]+$ && "$M" =~ ^[0-9]+$ ]] || [ "$H" -gt 23 ] || [ "$M" -gt 59 ]; then
  echo "Invalid time '$*'. Use HH:MM, e.g.  bash install-routine.sh 8:30"; exit 3
fi
[ -f "$DEST/checkrepo.py" ] || { echo "Install the scanner first: bash mac/install.sh"; exit 1; }

mkdir -p "$DEST" "$HOME/Library/LaunchAgents"
cp "$HERE/daily-check.sh" "$DEST/daily-check.sh" && chmod 755 "$DEST/daily-check.sh"
# fingerprints of the protection files (re-run this script after you update the kit)
: > "$DEST/fingerprints.txt"
for f in "$DEST/checkrepo.py" "$DEST/kitlib.py" "$DEST/github_check.py" "$DEST/autofix.py" "$DEST/malware-paths.txt" "$DEST/hooks/dispatch" "$DEST/bin/git-safeclone" "$DEST/daily-check.sh"; do
  [ -f "$f" ] && echo "$(shasum -a 256 "$f" | cut -d' ' -f1) $f" >> "$DEST/fingerprints.txt"
done
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$DEST/daily-check.sh</string></array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>$H</integer><key>Minute</key><integer>$M</integer></dict>
  <key>StandardOutPath</key><string>$DEST/reports/launchd.log</string>
  <key>StandardErrorPath</key><string>$DEST/reports/launchd.log</string>
</dict></plist>
EOF
mkdir -p "$DEST/reports"
launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null
launchctl bootstrap "gui/$(id -u)" "$PLIST" && echo "✔ daily check scheduled for $(printf '%02d:%02d' "$H" "$M") every day"
echo "  Run it now:      bash $DEST/daily-check.sh"
echo "  Reports:         $DEST/reports/"
echo "  Choose folders:  list your project folders in $DEST/projects.txt (one per line)"
echo "  Remove:          bash install-routine.sh --remove"
