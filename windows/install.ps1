# Ardvane - installer for Windows (BETA: written carefully but not yet tested on real Windows;
# please report results in the repository's issues).
#
# Run from PowerShell in the repository folder:
#   powershell -ExecutionPolicy Bypass -File .\windows\install.ps1            (add -DryRun to preview)
#
# Installs into %USERPROFILE%\.checkrepo :
#   checkrepo.py, bin\checkrepo.cmd   the read-only malware scanner + `checkrepo` command (added to your user PATH)
#   hooks\*                            global git hooks (Git for Windows runs them with its bundled bash)
#   bin\safeclone.ps1                  safe `git clone` for PowerShell (profile function)
#   bin\git-safeclone                  safe `git clone` for Git Bash (~/.bashrc function)
# and hardens: npm ignore-scripts=true, VS Code / Cursor / Windsurf (automatic tasks off, Workspace Trust on).
# Undo: .\windows\uninstall.ps1

param([switch]$DryRun, [switch]$NoNpm, [switch]$NoEditor, [switch]$NoSafeClone, [switch]$ForceHooks)

$ErrorActionPreference = 'Stop'
$Scanner = Join-Path (Split-Path -Parent $PSScriptRoot) 'scanner'
$Dest = Join-Path $HOME '.checkrepo'
$Begin = '# >>> polinrider-survival-kit >>>'; $End = '# <<< polinrider-survival-kit <<<'
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
function Ok($m) { Write-Host "OK  $m" -ForegroundColor Green }
function Warn($m) { Write-Host "!   $m" -ForegroundColor Yellow }
function Do-It($desc, [scriptblock]$action) { if ($DryRun) { Write-Host "  [dry-run] $desc" } else { & $action } }
function Invoke-Native([scriptblock]$Block) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $Block } finally { $ErrorActionPreference = $old }
}
function Backup($path) { if ((Test-Path $path) -and -not (Test-Path "$path.bak-checkrepo")) { Copy-Item $path "$path.bak-checkrepo" } }
function Set-Block($path, $block, [switch]$Lf) {
    $s = if (Test-Path $path) { [IO.File]::ReadAllText($path) } else { '' }
    $s = [regex]::Replace($s, '(?s)\r?\n*' + [regex]::Escape($Begin) + '.*?' + [regex]::Escape($End) + '\r?\n?', "`n")
    Backup $path
    $dir = Split-Path -Parent $path; if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $text = $s.TrimEnd() + "`n`n" + $block + "`n"
    if ($Lf) { $text = $text -replace "`r`n", "`n" } else { $text = $text -replace "(?<!`r)`n", "`r`n" }
    [IO.File]::WriteAllText($path, $text.TrimStart(), $Utf8NoBom)     # no BOM: a BOM breaks Git Bash's .bashrc
}

Write-Host "Ardvane installer for Windows (beta)$(if ($DryRun) {' - dry run, nothing will change'})`n"

# ---------------------------------------------------------------- prerequisites
$git = Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $git) { Write-Host 'Git for Windows is required: https://git-scm.com/download/win' -ForegroundColor Red; exit 1 }
$py = $null
foreach ($c in @('py', 'python', 'python3')) {
    $cmd = Get-Command $c -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cmd) { continue }
    $a = @(); if ($c -eq 'py') { $a = @('-3') }
    Invoke-Native { & $cmd.Source @a -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" 2>$null | Out-Null }
    if ($LASTEXITCODE -eq 0) { $py = @{ Name = $c; Exe = $cmd.Source; Args = $a }; break }   # skips the Microsoft Store stub
}
if (-not $py) { Write-Host 'Python 3.8+ is required: https://www.python.org/downloads/ (tick "Add python.exe to PATH")' -ForegroundColor Red; exit 1 }
Ok "git and Python found ($($py.Exe))"

$policy = Get-ExecutionPolicy -Scope CurrentUser
if ($policy -in @('Undefined', 'Restricted', 'AllSigned') -and (Get-ExecutionPolicy) -in @('Restricted', 'AllSigned')) {
    Warn "PowerShell is set to block profile scripts ($((Get-ExecutionPolicy))). Safe clone in PowerShell needs:"
    Warn "    Set-ExecutionPolicy -Scope CurrentUser RemoteSigned"
    Warn "  (without it, new PowerShell windows show an error loading your profile). Git Bash safe clone works either way."
}

# ---------------------------------------------------------------- files
Do-It 'copy scanner, hooks and safe-clone into %USERPROFILE%\.checkrepo' {
    New-Item -ItemType Directory -Force -Path "$Dest\bin", "$Dest\hooks" | Out-Null
    Copy-Item "$Scanner\checkrepo.py" "$Dest\checkrepo.py" -Force
    foreach ($f in 'kitlib.py', 'github_check.py', 'autofix.py') { Copy-Item "$Scanner\$f" "$Dest\$f" -Force }   # shared helpers, GitHub check, fixer
    Copy-Item "$Scanner\lists\malware-paths.txt" "$Dest\malware-paths.txt" -Force
    Copy-Item "$Scanner\safeclone\git-safeclone" "$Dest\bin\git-safeclone" -Force
    Copy-Item "$PSScriptRoot\safeclone.ps1" "$Dest\bin\safeclone.ps1" -Force
    $hooks = 'applypatch-msg','pre-applypatch','post-applypatch','pre-commit','pre-merge-commit','prepare-commit-msg',
             'commit-msg','post-commit','pre-rebase','post-checkout','post-merge','pre-push','pre-receive','update',
             'proc-receive','post-receive','post-update','push-to-checkout','pre-auto-gc','post-rewrite','sendemail-validate'
    $dispatch = ([IO.File]::ReadAllText("$Scanner\hooks\dispatch")) -replace "`r`n", "`n"      # hooks must have LF line endings
    foreach ($h in @('dispatch') + $hooks) { [IO.File]::WriteAllText("$Dest\hooks\$h", $dispatch, $Utf8NoBom) }   # copies: symlinks need admin
    # call Python by command name (not a full path) so the .cmd works whatever characters your user folder contains
    $pyCall = if ($py.Name -eq 'py') { 'py -3' } else { $py.Name }
    [IO.File]::WriteAllText("$Dest\bin\checkrepo.cmd", "@$pyCall `"%USERPROFILE%\.checkrepo\checkrepo.py`" %*`r`n", (New-Object System.Text.ASCIIEncoding))
    Get-ChildItem $Dest -Recurse -File | Unblock-File -ErrorAction SilentlyContinue   # files from a downloaded zip carry a "blocked" mark
}
Ok 'scanner installed in %USERPROFILE%\.checkrepo'

Do-It 'add %USERPROFILE%\.checkrepo\bin to your user PATH' {
    $p = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($null -eq $p) { $p = '' }
    if (($p -split ';') -notcontains "$Dest\bin") { [Environment]::SetEnvironmentVariable('Path', ($p.TrimEnd(';') + ";$Dest\bin").TrimStart(';'), 'User') }
}
Ok 'checkrepo command added to PATH (cmd and PowerShell)'

# ---------------------------------------------------------------- global git hooks
$current = Invoke-Native { & $git.Source config --global --get core.hooksPath 2>$null }
$ours = ($Dest -replace '\\', '/') + '/hooks'
if (-not $current -or $current -eq $ours -or $ForceHooks) {
    Do-It "git config --global core.hooksPath $ours" {
        if ($current -and $current -ne $ours) { [IO.File]::WriteAllText("$Dest\previous-hooksPath", $current, $Utf8NoBom) }
        & $git.Source config --global core.hooksPath $ours
        New-Item -ItemType File -Force -Path "$Dest\hooks-enabled" | Out-Null
    }
    Ok 'git hooks on: scan after clone/pull/checkout, block infected pushes'
} else {
    Remove-Item "$Dest\hooks-enabled" -ErrorAction SilentlyContinue
    Warn "you already use a global hooks folder: $current - not changed."
    Warn "  Re-run with -ForceHooks (your old setting is saved and restored on uninstall), or call the kit from each hook,"
    Warn "  e.g. in your pre-push hook:  ~/.checkrepo/hooks/pre-push `"`$@`" || exit 1"
}

# ---------------------------------------------------------------- safe clone (PowerShell + Git Bash)
if (-not $NoSafeClone) {
    $psBlock = @"
$Begin
# safe clone: scans before writing project files (bypass once with: git.exe clone ...)
function git {
    `$real = (Get-Command git.exe -CommandType Application | Select-Object -First 1).Source
    if (`$args.Count -gt 0 -and `$args[0] -eq 'clone') { & "`$HOME\.checkrepo\bin\safeclone.ps1" @(`$args | Select-Object -Skip 1) }
    else { & `$real @args }
}
$End
"@
    Do-It "add safe-clone function to $PROFILE" { Set-Block $PROFILE $psBlock }
    $bashBlock = "$Begin`nexport PATH=`"`$HOME/.checkrepo/bin:`$PATH`"`n" +
                 "checkrepo() { py -3 `"`$HOME/.checkrepo/checkrepo.py`" `"`$@`" 2>/dev/null || python `"`$HOME/.checkrepo/checkrepo.py`" `"`$@`"; }`n" +
                 "function git { if [ `"`$1`" = `"clone`" ]; then shift; bash `"`$HOME/.checkrepo/bin/git-safeclone`" `"`$@`"; else command git `"`$@`"; fi; }`n$End"
    Do-It 'add safe-clone function and checkrepo command to ~/.bashrc (Git Bash)' { Set-Block (Join-Path $HOME '.bashrc') $bashBlock -Lf }
    Ok 'safe clone on for PowerShell and Git Bash (cmd.exe, `gh repo clone` and GUI clones get the post-clone warning instead)'
}

# ---------------------------------------------------------------- npm
if (-not $NoNpm) {
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Do-It 'npm config set ignore-scripts true' { Invoke-Native { npm config set ignore-scripts true } }
        Ok 'npm: install scripts blocked (per trusted project if needed: npm install --ignore-scripts=false)'
    } else { Warn 'npm not found - skipped' }
}

# ---------------------------------------------------------------- editors
if (-not $NoEditor) {
    foreach ($f in @("$env:APPDATA\Code\User\settings.json", "$env:APPDATA\Cursor\User\settings.json", "$env:APPDATA\Windsurf\User\settings.json")) {
        if (-not (Test-Path (Split-Path -Parent $f))) { continue }
        Do-It "harden $f" {
            $raw = if (Test-Path $f) { [IO.File]::ReadAllText($f) } else { '{}' }
            if ([string]::IsNullOrWhiteSpace($raw)) { $raw = '{}' }
            $j = $null
            if ($raw -notmatch '(^|\s)//|/\*') { try { $j = $raw | ConvertFrom-Json } catch { $j = $null } }   # never rewrite files with comments
            if ($null -eq $j) {
                Warn "could not safely edit $f (it contains comments). Add these four settings by hand:"
                Write-Host '      "task.allowAutomaticTasks": "off",'
                Write-Host '      "security.workspace.trust.enabled": true,'
                Write-Host '      "security.workspace.trust.startupPrompt": "always",'
                Write-Host '      "security.workspace.trust.untrustedFiles": "prompt"'
            } else {
                Backup $f
                $j | Add-Member -NotePropertyName 'task.allowAutomaticTasks' -NotePropertyValue 'off' -Force
                $j | Add-Member -NotePropertyName 'security.workspace.trust.enabled' -NotePropertyValue $true -Force
                $j | Add-Member -NotePropertyName 'security.workspace.trust.startupPrompt' -NotePropertyValue 'always' -Force
                $j | Add-Member -NotePropertyName 'security.workspace.trust.untrustedFiles' -NotePropertyValue 'prompt' -Force
                [IO.File]::WriteAllText($f, ($j | ConvertTo-Json -Depth 20), $Utf8NoBom)
                Ok "editor hardened: $f"
            }
        }
    }
}

# ---------------------------------------------------------------- self-test
if (-not $DryRun -and (Test-Path "$Scanner\tests\run_tests.py")) {
    $env:CHECKREPO = "$Dest\checkrepo.py"
    Invoke-Native { & $py.Exe @($py.Args) "$Scanner\tests\run_tests.py" --quiet }
    if ($LASTEXITCODE -eq 0) { Ok 'self-test passed' } else { Warn 'self-test reported problems - see above (please report them!)' }
}
Write-Host "`nDone. Open a NEW PowerShell window, then try:  checkrepo --version" -ForegroundColor Green
Write-Host 'Optional daily check:  powershell -ExecutionPolicy Bypass -File .\windows\install-routine.ps1'
