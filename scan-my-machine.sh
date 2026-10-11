#!/usr/bin/env bash
# Ardvane — one-command, READ-ONLY scan of this computer (macOS / Linux).
# Nothing is installed, changed, deleted or run from your projects. No internet connection is needed.
#
#   bash scan-my-machine.sh            scan your home folder (projects up to 6 folders deep)
#   bash scan-my-machine.sh --quick    skip the full project/package scan (machine checks only)
#   bash scan-my-machine.sh PATH ...   scan these project folders instead of your whole home folder
#
# Exit code: 0 clean, 1 malware evidence found, 2 only items worth a look.
# A copy of the report is saved as scan-report-YYYY-MM-DD-HHMM.txt in ~/.checkrepo/reports/scans, where the
# dashboard lists it (or in $SCAN_REPORT_DIR). Never inside the app's own folder, which upgrades replace.
# For the dashboard: if $SCAN_EVENTS names a file, every result is also appended to it as
# tab-separated lines: TYPE <tab> message <tab> path  (TYPE: H section, D danger, W check, O ok, I info, P progress, R result)

set -u
KIT="$(cd "$(dirname "$0")" && pwd)"
CHECKREPO="$KIT/scanner/checkrepo.py"
PKGCHECK="$KIT/scanner/check-my-projects.py"
QUICK=0; ROOTS=()
for a in "$@"; do case "$a" in
  --quick) QUICK=1 ;; -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  -*) echo "unknown option: $a"; exit 3 ;; *) ROOTS+=("$a") ;; esac; done
[ ${#ROOTS[@]} -eq 0 ] && ROOTS=("$HOME")
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
OS="$(uname)"
REPORT_DIR="${SCAN_REPORT_DIR:-$HOME/.checkrepo/reports/scans}"
mkdir -p "$REPORT_DIR" 2>/dev/null
[ -w "$REPORT_DIR" ] || { REPORT_DIR="${TMPDIR:-/tmp}"; }
if [ -n "${ARDVANE_INSTALLED:-}" ]; then PROTECT="ardvane protect"; else PROTECT="bash $KIT/mac/install.sh"; fi
REPORT="$REPORT_DIR/scan-report-$(date +%Y-%m-%d-%H%M).txt"
if [ -t 1 ]; then R=$'\033[1;31m'; Y=$'\033[1;33m'; G=$'\033[1;32m'; B=$'\033[1m'; D=$'\033[2m'; X=$'\033[0m'; else R=; Y=; G=; B=; D=; X=; fi
danger=0; warn=0
say()  { echo "$*"; echo "$*" | sed $'s/\x1b\\[[0-9;]*m//g' >> "$REPORT"; }
# ev TYPE MESSAGE [PATH] — machine-readable copy for the dashboard (no-op unless $SCAN_EVENTS is set)
ev()   { [ -n "${SCAN_EVENTS:-}" ] && printf '%s\t%s\t%s\n' "$1" "$(printf '%s' "$2" | tr '\t\n' '  ')" "${3:-}" >> "$SCAN_EVENTS"; return 0; }
bad()  { danger=$((danger+1)); say "  ${R}🛑 $1${X}"; ev D "$1" "${2:-}"; }
chk()  { warn=$((warn+1)); say "  ${Y}⚠️  $1${X}"; ev W "$1" "${2:-}"; }
okay() { say "  ${G}✅ $1${X}"; ev O "$1"; }
info() { say "  ${D}$1${X}"; ev I "$1"; }
head1() { say ""; say "${B}$1${X}"; ev H "$1"; }
: > "$REPORT"

PY=""
for c in python3 python; do
  command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1 && { PY="$c"; break; }
done

say "${B}Ardvane — machine scan${X}  ${D}$(date '+%Y-%m-%d %H:%M') · read-only · $OS${X}"
[ -n "$PY" ] || say "${Y}Python 3.8+ not found — project and package scans will be skipped (macOS: xcode-select --install)${X}"

# ------------------------------------------------------------------ 1. known malware locations
head1 "1. Known malware locations"
n=$danger
for p in "$HOME/Library/Application Support/VSCodeUpdater" "$HOME/.node_modules" "$HOME/.n2" "$HOME/.n3" "$HOME/.npl" "$HOME/.pyp" \
         "$HOME/.sysinfo" "$HOME/Library/Application Support/MicrosoftSystem64" "$HOME/.local/share/MicrosoftSystem64" "$HOME/.pcl-data" \
         "$HOME/.pcl-state" "$HOME/Library/LaunchAgents/com.launchkeeper.MicrosoftSystem64.plist" "$HOME/Library/LaunchAgents/com.bablu.helper.plist" \
         "$HOME/Library/LaunchAgents/com.avatar.update.wake.plist" "$HOME/.config/systemd/user/MicrosoftSystem64.service" \
         "$HOME/.config/autostart/MicrosoftSystem64.desktop" /tmp/0001.dat /tmp/tmp7A863DD1.tmp; do
  [ -e "$p" ] && bad "found: ${p/#$HOME/~}" "$p"
done
# loose scripts dropped into Application Support (the dropper hid in a folder with an innocent name)
if [ -d "$HOME/Library/Application Support" ] && [ -n "$PY" ]; then
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if "$PY" - "$CHECKREPO" "$f" <<'PYEOF'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("cr", sys.argv[1]); cr = importlib.util.module_from_spec(spec); spec.loader.exec_module(cr)
t = open(sys.argv[2], encoding="utf-8", errors="replace").read(5_000_000)
sys.exit(0 if (cr.marker_hits(t) or cr.looks_obfuscated(t)) else 1)
PYEOF
    then bad "malware script: ${f/#$HOME/~}" "$f"; fi
  done < <(find "$HOME/Library/Application Support" -maxdepth 2 -type f \( -name "*.js" -o -name "*.cjs" -o -name "*.mjs" \) -size +10k 2>/dev/null \
           | grep -vE "/Application Support/(Code|Cursor|Windsurf|Claude|Google|Slack|Notion|Microsoft|Docker|Linear|Figma|Discord|BraveSoftware|Arc|Chromium|Firefox|Electron|JetBrains)/")
fi
[ $danger -eq $n ] && okay "none"

# ------------------------------------------------------------------ 2. processes
head1 "2. Running processes"
n=$danger; nw=$warn
plist="$(ps -axo pid=,args= 2>/dev/null | grep -v -e "scan-my-machine" -e "grep")"
while IFS= read -r l; do [ -n "$l" ] && bad "process: ${l:0:150}"; done < <(printf '%s\n' "$plist" | grep -E \
  "MicrosoftSystem64|SvcHostUpdate|MicrosoftCLROptimization|tg14xq|VSCodeUpdater|/\.node_modules/|/\.n[23]/|/\.npl|node [^ ]*\.(eot|woff2?|ttf|otf|llf)( |$)")
while IFS= read -r l; do [ -n "$l" ] && chk "inline node process fetching/decoding code: ${l:0:150}"; done < <(printf '%s\n' "$plist" | grep -E "node -e " | grep -E "https?://|eval|base64|Buffer\.from|atob")
[ $danger -eq $n ] && [ $warn -eq $nw ] && okay "nothing suspicious"

# ------------------------------------------------------------------ 3. startup items
head1 "3. Programs that start automatically"
n=$danger; nw=$warn; count=0
IOC_START='MicrosoftSystem64|launchkeeper|bablu|avatar\.update|SvcHostUpdate|VSCodeUpdater|tg14xq'
if [ "$OS" = "Darwin" ]; then
  for f in "$HOME"/Library/LaunchAgents/*.plist /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist; do
    [ -f "$f" ] || continue; count=$((count+1)); name="$(basename "$f")"
    prog="$(plutil -extract ProgramArguments json -o - "$f" 2>/dev/null || plutil -extract Program raw -o - "$f" 2>/dev/null)"
    if printf '%s %s' "$name" "$prog" | grep -Eq "$IOC_START"; then bad "malware startup item: $f" "$f"; continue; fi
    case "$name" in com.apple.*) chk "Apple-named item in a third-party folder (fake Apple names are a red flag): $f" "$f"; continue ;; esac
    if printf '%s' "$prog" | grep -Eq '/tmp/|/private/var/folders/|/Users/Shared/|/\.[A-Za-z0-9_-]+/|curl|wget|base64|osascript|"-e"|"-c"|\.js"|\.py"'; then
      chk "startup item runs a script / hidden or temporary file — check you recognise it: $f" "$f"
      continue
    fi
    exe="$(printf '%s' "$prog" | "${PY:-python3}" -c 'import json,sys
d=sys.stdin.read().strip()
try: v=json.loads(d); print(v[0] if isinstance(v,list) and v else v)
except Exception: print(d)' 2>/dev/null)"
    if [ -n "$exe" ] && [ -f "$exe" ] && ! codesign -v "$exe" >/dev/null 2>&1; then
      chk "startup item runs an unsigned program — check you recognise it: $exe" "$exe"
    fi
  done
  items="$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null)"
  [ -n "$items" ] && info "login items: $items"
else
  for f in "$HOME"/.config/systemd/user/*.service "$HOME"/.config/autostart/*.desktop; do
    [ -f "$f" ] || continue; count=$((count+1))
    grep -Eq "$IOC_START" "$f" && { bad "malware startup item: $f" "$f"; continue; }
    grep -Eq '/tmp/|/\.[A-Za-z0-9_-]+/|curl|wget|base64|node -e|python3? -c' "$f" && chk "startup item runs a script / hidden file — check it: $f" "$f"
  done
fi
cron="$(crontab -l 2>/dev/null)"
[ -n "$cron" ] && printf '%s' "$cron" | grep -qE "curl|wget|node|python|base64|/tmp/" && chk "a scheduled cron job runs a download/script — review it: crontab -l"
[ $danger -eq $n ] && [ $warn -eq $nw ] && okay "$count startup item(s), nothing suspicious"

# ------------------------------------------------------------------ 4. shell files, hosts
head1 "4. Shell startup files and hosts file"
n=$danger; nw=$warn
for f in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile" "$HOME/.config/fish/config.fish"; do
  [ -f "$f" ] || continue
  grep -Eq "$IOC_START|/\.n[23]/|/\.npl" "$f" && { bad "malware reference in ${f/#$HOME/~}" "$f"; continue; }
  hit="$(grep -nE 'curl[^|#]*\|[[:space:]]*(ba|z)?sh|wget[^|#]*\|[[:space:]]*(ba|z)?sh|base64 (-d|--decode)|node -e|python3? -c|eval "\$\((curl|wget)' "$f" | head -1)"
  [ -n "$hit" ] && chk "${f/#$HOME/~} line ${hit%%:*} runs downloaded/encoded code — check you added it: ${hit#*:}" "$f"
done
extra="$(grep -vE '^[[:space:]]*(#|$)|localhost|broadcasthost|ip6-|::1' /etc/hosts 2>/dev/null)"
[ -n "$extra" ] && chk "/etc/hosts has custom entries (fine if you added them): $(echo "$extra" | head -3 | tr '\n' ' ')"
[ $danger -eq $n ] && [ $warn -eq $nw ] && okay "nothing suspicious"

# ------------------------------------------------------------------ 5. network
head1 "5. Connections to known attacker servers"
C2='166\.88\.(54\.158|134\.62|134\.75|134\.82|4\.2|73\.46)|198\.105\.127\.210|23\.27\.(202\.27|120\.142|13\.43|13\.135|20\.187)|154\.91\.0\.103|188\.43\.33\.249|202\.155\.8\.173|136\.0\.9\.8|179\.43\.166\.242|195\.201\.194\.107|193\.247\.144\.38|45\.137\.198\.133|181\.214\.149\.14[78]|91\.218\.183\.174|150\.251\.113\.223'
if command -v lsof >/dev/null; then
  hit="$(lsof -nP -iTCP 2>/dev/null | grep -E -- "->($C2):" | head -1)"
  if [ -n "$hit" ]; then bad "connection to a known attacker server: $hit"; else okay "none"; fi
else info "(lsof not available — skipped)"; fi

# ------------------------------------------------------------------ 6. editors
head1 "6. Code editor settings and extensions"
n=$danger; nw=$warn
for s in "$HOME/Library/Application Support/Code/User" "$HOME/Library/Application Support/Cursor/User" "$HOME/Library/Application Support/Windsurf/User" \
         "$HOME/.config/Code/User" "$HOME/.config/Cursor/User"; do
  [ -d "$s" ] || continue; ed="$(basename "$(dirname "$s")")"
  [ -f "$s/settings.json" ] && grep -Eq '"task\.allowAutomaticTasks"[[:space:]]*:[[:space:]]*("on"|true)' "$s/settings.json" && chk "$ed: automatic tasks are ON — any folder you open can run code (the kit's installer turns this off)"
  [ -f "$s/settings.json" ] && grep -Eq '"security\.workspace\.trust\.enabled"[[:space:]]*:[[:space:]]*false' "$s/settings.json" && chk "$ed: Workspace Trust is OFF"
  [ -f "$s/tasks.json" ] && grep -q folderOpen "$s/tasks.json" && chk "$ed: a global user task runs on every folder open — check $s/tasks.json" "$s/tasks.json"
done
for e in "$HOME/.vscode/extensions" "$HOME/.cursor/extensions" "$HOME/.windsurf/extensions"; do
  [ -d "$e" ] || continue
  total=$(find "$e" -maxdepth 1 -mindepth 1 -type d | wc -l | tr -d ' ')
  recent=$(find "$e" -maxdepth 1 -mindepth 1 -type d -mtime -14 2>/dev/null | sed 's#.*/##' | tr '\n' ' ')
  info "$(basename "$(dirname "$e")") extensions: $total installed${recent:+; added/updated in the last 14 days: $recent}"
done
[ $danger -eq $n ] && [ $warn -eq $nw ] && okay "safe settings"

# ------------------------------------------------------------------ 7. projects
head1 "7. Your projects (every git repository + loose downloads)"
if [ $QUICK -eq 1 ] || [ -z "$PY" ]; then
  info "skipped"
else
  repos=0; dn=$danger; wn=$warn
  # scan_dir DIR LABEL: report checkrepo's verdict. No result (a crash, a hang) is "could not scan", never clean.
  scan_dir() {
    local line where="${1/#$HOME/~}"
    line="$("$PY" "$CHECKREPO" --summary "$1" 2>/dev/null)"
    case "${line%% *}" in
      0) ;;
      1) printf '\r%80s\r' '' >&2; bad "INFECTED: $2${where} — ${line#* }" "$1" ;;
      2) printf '\r%80s\r' '' >&2; chk "worth a look: $2${where} — ${line#* }" "$1" ;;
      *) printf '\r%80s\r' '' >&2; chk "could not scan ${where} (${line#* }) — run: checkrepo \"$where\"" "$1" ;;
    esac
  }
  while IFS= read -r g; do
    d="$(dirname "$g")"; repos=$((repos+1))
    printf '\r  scanning %d: %-60.60s' "$repos" "${d/#$HOME/~}" >&2; ev P "$repos ${d/#$HOME/~}"
    scan_dir "$d" ""
  done < <(find "${ROOTS[@]}" -maxdepth 6 \( -name node_modules -o -name Library -o -name .Trash -o -name .cache -o -name .npm -o -name .cargo -o -name .rustup -o -name .gradle -o -name .m2 \) -prune -o -name .git -type d -print 2>/dev/null)
  printf '\r%80s\r' '' >&2
  for dl in "$HOME/Downloads" "$HOME/Desktop"; do
    [ -d "$dl" ] && scan_dir "$dl" "files in "
  done
  if [ $repos -eq 0 ]; then chk "found 0 git repositories — if your projects live elsewhere, run: bash scan-my-machine.sh /path/to/projects"
  elif [ $danger -eq $dn ] && [ $warn -eq $wn ]; then okay "$repos repositories + Downloads/Desktop scanned — no malware"
  else info "$repos repositories scanned"; fi
fi

# ------------------------------------------------------------------ 8. packages
head1 "8. Known malicious packages (npm / PyPI / Packagist, incl. global installs)"
if [ $QUICK -eq 1 ] || [ -z "$PY" ]; then
  info "skipped"
else
  out="$("$PY" "$PKGCHECK" "${ROOTS[@]}" 2>/dev/null)"; prc=$?
  if [ $prc -eq 1 ]; then while IFS= read -r l; do case "$l" in *"[npm]"*|*"[pypi]"*|*"[packagist]"*) bad "malicious package: $(echo "$l" | sed 's/^ *//')" "$(echo "$l" | sed 's/^.*)  //; s#^~#'"$HOME"'#')" ;; esac; done <<< "$out"
  else okay "none of the known-malicious packages are used or installed"; fi
fi

# ------------------------------------------------------------------ 9. system protections
head1 "9. Built-in protections"
if [ "$OS" = "Darwin" ]; then
  csrutil status 2>/dev/null | grep -q enabled && okay "System Integrity Protection on" || chk "System Integrity Protection is OFF"
  spctl --status 2>/dev/null | grep -q enabled && okay "Gatekeeper on" || chk "Gatekeeper is OFF"
  fdesetup status 2>/dev/null | grep -q "On" && okay "FileVault disk encryption on" || chk "FileVault disk encryption is off"
  /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q enabled && okay "Firewall on" || chk "Firewall is off"
else
  info "(Linux: check your distribution's firewall and disk encryption settings)"
fi
npmset="$(command -v npm >/dev/null && npm config get ignore-scripts 2>/dev/null)"
[ "$npmset" = "true" ] && okay "npm install scripts blocked" || info "npm install scripts are allowed (the kit's installer blocks them)"
hp="$(git config --global --get core.hooksPath 2>/dev/null)"
[ -n "$hp" ] && info "global git hooks folder: $hp" || info "no automatic git scanning yet (install the kit to add it)"

# ------------------------------------------------------------------ verdict
say ""
if [ $danger -gt 0 ]; then
  say "${R}${B}RESULT: INFECTED — $danger serious finding(s).${X}"
  say "Do NOT open the affected projects or run npm install in them. From another device if possible, follow:"
  say "  $KIT/docs/after-a-scan/if-danger-found.md   (cut off access first, then clean)"
  code=1
elif [ $warn -gt 0 ]; then
  say "${Y}${B}RESULT: no malware found — $warn item(s) worth a look (often harmless — read each line above).${X}"
  code=2
else
  say "${G}${B}RESULT: CLEAN — no signs of this malware.${X}"
  code=0
fi
say "Protect yourself from now on (scans every clone/pull/push automatically):  $PROTECT"
say "${D}Report saved: $REPORT${X}"
ev R "$code" "$REPORT"
exit $code
