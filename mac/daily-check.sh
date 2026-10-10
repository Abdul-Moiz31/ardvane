#!/usr/bin/env bash
# polinrider-survival-kit — daily security check for macOS (read-only).
# Checks this Mac for the campaign's implants, persistence and C2 connections, scans your projects with
# checkrepo, verifies the kit's protections are still on, and writes a report + shows a notification.
#
# Run by hand:        bash daily-check.sh
# Run every morning:  bash install-routine.sh
# Report:             ~/.checkrepo/reports/YYYY-MM-DD.txt
# Projects scanned:   folders listed in ~/.checkrepo/projects.txt (one per line, # for comments),
#                     default ~/Documents ~/Desktop ~/Downloads ~/code ~/projects
# Note: when run by launchd, macOS may block reading Documents/Desktop/Downloads until you give
#       /bin/bash "Full Disk Access" (System Settings > Privacy & Security). The report tells you if that happens.

set -u
# launchd starts with a minimal PATH — add the usual places for Homebrew / npm / nvm
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH"
DEST="$HOME/.checkrepo"; mkdir -p "$DEST/reports"
REPORT="$DEST/reports/$(date +%Y-%m-%d).txt"
PY=""; for c in python3 python; do command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys' 2>/dev/null && { PY="$c"; break; }; done
danger=0; warn=0
out() { echo "$*" >> "$REPORT"; }
bad() { danger=$((danger+1)); out "  🛑 $*"; }
chk() { warn=$((warn+1)); out "  ⚠️  $*"; }
: > "$REPORT"
out "polinrider-survival-kit daily check — $(date '+%Y-%m-%d %H:%M')"
out ""

# ---------------------------------------------------------------- 1. implants & stealer folders
out "1. Known malware locations"
for p in "$HOME/Library/Application Support/VSCodeUpdater" "$HOME/.node_modules" "$HOME/.n2" "$HOME/.n3" "$HOME/.npl" "$HOME/.pyp" "$HOME/.sysinfo" \
         "$HOME/Library/Application Support/MicrosoftSystem64" "$HOME/.local/share/MicrosoftSystem64" "$HOME/.pcl-data" "$HOME/.pcl-state" \
         "$HOME/Library/LaunchAgents/com.launchkeeper.MicrosoftSystem64.plist" "$HOME/Library/LaunchAgents/com.bablu.helper.plist" \
         "$HOME/Library/LaunchAgents/com.avatar.update.wake.plist" /tmp/0001.dat /tmp/tmp7A863DD1.tmp; do
  [ -e "$p" ] && bad "found: ${p/#$HOME/~}"
done
[ $danger -eq 0 ] && out "  ✅ none"

# ---------------------------------------------------------------- 2. processes
out "2. Suspicious processes"
n=$danger
# match against the process list only (never against this script's own command line)
plist="$(ps -axo pid=,comm=,args= | grep -v -e "daily-check" -e "grep")"
procs="$(printf '%s\n' "$plist" | grep -E "MicrosoftSystem64|SvcHostUpdate|MicrosoftCLROptimization|tg14xq|VSCodeUpdater|/\.node_modules/|node [^ ]*\.(eot|woff2?|ttf|otf|llf)( |$)")"
[ -n "$procs" ] && while IFS= read -r l; do bad "process: ${l:0:160}"; done <<< "$procs"
# `node -e` is also used by legitimate tools: only serious when it fetches or decodes code
inline="$(printf '%s\n' "$plist" | grep -E "node -e " | grep -E "https?://|eval|base64|Buffer\.from|atob")"
[ -n "$inline" ] && while IFS= read -r l; do chk "inline node process fetching/decoding code: ${l:0:160}"; done <<< "$inline"
[ $danger -eq $n ] && [ -z "$inline" ] && out "  ✅ none"

# ---------------------------------------------------------------- 3. persistence changed in last 24h
out "3. Startup items / shell files changed in the last 24 hours"
n=$warn
while IFS= read -r f; do
  [ -n "$f" ] && [ "$(basename "$f")" != "com.polinrider-survival-kit.daily-check.plist" ] && chk "new/changed startup item: $f"
done < <(find "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons -type f -mtime -1 2>/dev/null)
for f in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile"; do
  [ -f "$f" ] && [ -n "$(find "$f" -mtime -1 2>/dev/null)" ] && chk "${f/#$HOME/~} changed — check it contains nothing you didn't add"
done
ls "$HOME/Library/LaunchAgents" /Library/LaunchAgents 2>/dev/null | grep -qi "^com\.apple\." && chk "Apple-named item in a third-party LaunchAgents folder (fake Apple names are a red flag)"
crontab -l 2>/dev/null | grep -qE "curl|wget|node|python|base64|/tmp/" && chk "crontab runs a download/script — review: crontab -l"
[ $warn -eq $n ] && out "  ✅ nothing unusual"

# ---------------------------------------------------------------- 4. network
out "4. Connections to known attacker servers"
C2='166\.88\.(54\.158|134\.62|134\.75|134\.82|4\.2|73\.46)|198\.105\.127\.210|23\.27\.(202\.27|120\.142|13\.43|13\.135|20\.187)|154\.91\.0\.103|188\.43\.33\.249|202\.155\.8\.173|136\.0\.9\.8|179\.43\.166\.242|195\.201\.194\.107|193\.247\.144\.38|45\.137\.198\.133|181\.214\.149\.14[78]|91\.218\.183\.174|150\.251\.113\.223'
# anchored: the remote address follows "->" and is followed by ":port", so 123.27.13.43 or 136.0.9.80 can't match
hit="$(lsof -nP -iTCP 2>/dev/null | grep -E -- "->($C2):" | head -1)"
if [ -n "$hit" ]; then bad "connection to a known attacker server: $hit"; else out "  ✅ none"; fi

# ---------------------------------------------------------------- 5. projects
out "5. Projects (checkrepo)"
if [ -n "$PY" ] && [ -f "$DEST/checkrepo.py" ]; then
  roots=(); cand=()
  if [ -f "$DEST/projects.txt" ]; then
    while IFS= read -r l || [ -n "$l" ]; do
      l="${l%%#*}"; l="$(printf '%s' "$l" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"   # drop comments / blanks
      [ -n "$l" ] && cand+=("${l/#\~/$HOME}")
    done < "$DEST/projects.txt"
  else
    cand=("$HOME/Documents" "$HOME/Desktop" "$HOME/Downloads" "$HOME/code" "$HOME/projects")
  fi
  for d in ${cand[@]+"${cand[@]}"}; do
    if [ ! -d "$d" ]; then [ -f "$DEST/projects.txt" ] && chk "folder in projects.txt not found: $d"; continue; fi
    if ls "$d" >/dev/null 2>&1; then roots+=("$d")
    else chk "can't read ${d/#$HOME/~} — give /bin/bash Full Disk Access (System Settings › Privacy & Security) so the daily check can scan it"; fi
  done
  repos=0
  [ ${#roots[@]} -gt 0 ] && while IFS= read -r g; do
    d="$(dirname "$g")"; repos=$((repos+1))
    res="$("$PY" "$DEST/checkrepo.py" --json "$d" 2>/dev/null)"
    code="$(printf '%s' "$res" | "$PY" -c 'import json,sys
try: print(json.load(sys.stdin)["exit"])
except Exception: print(-1)')"
    detail="$(printf '%s' "$res" | "$PY" -c 'import json,sys
try: print("; ".join(f[2]+": "+f[3] for f in json.load(sys.stdin)["findings"][:3]))
except Exception: pass')"
    case "$code" in 1) bad "DANGER in ${d/#$HOME/~}: $detail" ;; 2) chk "worth a look in ${d/#$HOME/~}: $detail" ;; esac
  done < <(find "${roots[@]}" -maxdepth 5 -name .git -type d -not -path "*/node_modules/*" 2>/dev/null)
  if [ $repos -eq 0 ]; then chk "scanned 0 repositories — nothing was checked. List your project folders in ~/.checkrepo/projects.txt"
  else out "  scanned $repos repositories"; fi
  [ -d "$HOME/Downloads" ] && [ "$("$PY" "$DEST/checkrepo.py" --json "$HOME/Downloads" 2>/dev/null | "$PY" -c 'import json,sys
try: print(json.load(sys.stdin)["exit"])
except Exception: print(0)')" = "1" ] && bad "DANGER in ~/Downloads — run: checkrepo ~/Downloads"
else
  chk "checkrepo is not installed — run ../../mac/install.sh"
fi

# ---------------------------------------------------------------- 6. protections still on
out "6. Protections"
n=$danger; nw=$warn
hp="$(git config --global --get core.hooksPath 2>/dev/null)"
if [ "$hp" != "$DEST/hooks" ]; then
  if [ -f "$DEST/hooks-enabled" ]; then bad "TAMPERED: global git hooks were turned off (core.hooksPath='$hp') — re-run the installer"
  else chk "git hooks are not enabled (you kept your own hooks folder) — clones/pushes aren't scanned automatically"; fi
fi
if [ -f "$DEST/fingerprints.txt" ]; then
  while read -r sum file; do
    [ -f "$file" ] && [ "$(shasum -a 256 "$file" | cut -d' ' -f1)" != "$sum" ] && bad "TAMPERED: ${file/#$HOME/~} was modified"
  done < "$DEST/fingerprints.txt"
fi
command -v npm >/dev/null && [ "$(npm config get ignore-scripts 2>/dev/null)" != "true" ] && chk "npm ignore-scripts is off"
s="$HOME/Library/Application Support/Code/User/settings.json"
[ -f "$s" ] && ! grep -q '"task.allowAutomaticTasks": *"off"' "$s" && chk "VS Code automatic tasks are not off"
for e in $(find "$HOME/.vscode/extensions" "$HOME/.cursor/extensions" -maxdepth 1 -mindepth 1 -type d -mtime -1 2>/dev/null); do chk "editor extension installed/updated in last 24h: $(basename "$e") — make sure you trust its publisher"; done
csrutil status 2>/dev/null | grep -q enabled || chk "System Integrity Protection is not enabled"
spctl --status 2>/dev/null | grep -q enabled || chk "Gatekeeper is not enabled"
[ $danger -eq $n ] && [ $warn -eq $nw ] && out "  ✅ intact"

# ---------------------------------------------------------------- 7. GitHub account (opt-in, set in the dashboard's Settings)
gh_user=""
[ -n "$PY" ] && [ -f "$DEST/settings.json" ] && gh_user="$("$PY" -c 'import json,sys
try:
    s = json.load(open(sys.argv[1], encoding="utf-8")); print(s.get("github_user", "") if s.get("github_enabled") else "")
except Exception: pass' "$DEST/settings.json" 2>/dev/null)"
if [ -n "$gh_user" ] && [ -f "$DEST/github_check.py" ]; then
  out "7. GitHub account @$gh_user"
  ghout="$("$PY" "$DEST/github_check.py" "$gh_user" 2>&1)"; ghrc=$?
  while IFS= read -r l; do
    case "$l" in
      *"🛑"*) danger=$((danger+1)); out "$l" ;;
      *"⚠️"*) warn=$((warn+1)); out "$l" ;;
      "") ;;
      *) out "  $l" ;;
    esac
  done <<< "$ghout"
  [ $ghrc -eq 3 ] && chk "the GitHub check could not run (see the line above)"
fi

# ---------------------------------------------------------------- 8. automatic fixes (only in "Automatic" mode)
if [ -n "$PY" ] && [ -f "$DEST/autofix.py" ] && [ "$("$PY" -c 'import json,sys
try: print(json.load(open(sys.argv[1], encoding="utf-8")).get("autofix", "ask"))
except Exception: print("ask")' "$DEST/settings.json" 2>/dev/null)" = "auto" ]; then
  fixed="$("$PY" "$DEST/autofix.py" auto 2>&1)"
  if [ -n "$fixed" ]; then
    out "8. Automatic fixes"
    while IFS= read -r l; do out "$l"; done <<< "$fixed"
    [ $danger -gt 0 ] && out "  Files were removed from this computer, but anything stolen before is still stolen — finish the recovery checklist."
  fi
fi

# ---------------------------------------------------------------- verdict
out ""
if [ $danger -gt 0 ]; then verdict="ACTION NEEDED — $danger serious finding(s). Don't open affected projects; see docs/after-a-scan/if-danger-found.md"
elif [ $warn -gt 0 ]; then verdict="Clean, $warn item(s) worth a look"
else verdict="ALL CLEAN — no signs of malware, protections intact"; fi
{ echo "VERDICT: $verdict"; echo; cat "$REPORT"; } > "$REPORT.tmp" && mv "$REPORT.tmp" "$REPORT"
cat "$REPORT"
[ -z "${CHECKREPO_NO_NOTIFY:-}" ] && osascript -e "display notification \"$verdict\" with title \"Daily security check\" subtitle \"Report: ~/.checkrepo/reports\"" 2>/dev/null
[ $danger -gt 0 ] && exit 1 || exit 0
