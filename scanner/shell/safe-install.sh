# safe install: npm / npx / pnpm / yarn / bun / pip check packages for known malware before installing them.
# Each command goes through Ardvane's checker first (it decides what installs: `npm run dev` returns at once) and runs
# only if the checker didn't block it (exit 10). If the checker is missing or fails, the command runs as normal.
# Bypass once, only if you are sure:  command npm install ...
__ardvane_safe_install() { "$HOME/.checkrepo/bin/safe-install" "$@"; [ $? -ne 10 ]; }
npm()  { __ardvane_safe_install npm  "$@" && command npm  "$@"; }
npx()  { __ardvane_safe_install npx  "$@" && command npx  "$@"; }
pnpm() { __ardvane_safe_install pnpm "$@" && command pnpm "$@"; }
yarn() { __ardvane_safe_install yarn "$@" && command yarn "$@"; }
bun()  { __ardvane_safe_install bun  "$@" && command bun  "$@"; }
bunx() { __ardvane_safe_install bunx "$@" && command bunx "$@"; }
pip()  { __ardvane_safe_install pip  "$@" && command pip  "$@"; }
pip3() { __ardvane_safe_install pip3 "$@" && command pip3 "$@"; }
