# Ardvane - uninstaller for Windows (BETA). Reverses install.ps1 and install-routine.ps1.
# Leaves npm ignore-scripts and editor settings in place (good defaults); how to revert them is printed at the end.
#   powershell -ExecutionPolicy Bypass -File .\windows\uninstall.ps1

$Dest = Join-Path $HOME '.checkrepo'
$Begin = '# >>> polinrider-survival-kit >>>'; $End = '# <<< polinrider-survival-kit <<<'
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
$git = (Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source

# 1. daily routine
if (Get-ScheduledTask -TaskName 'polinrider-survival-kit daily check' -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName 'polinrider-survival-kit daily check' -Confirm:$false
    Write-Host 'OK  daily check removed'
}

# 2. git hooks (restore a previous global hooks folder if the installer replaced one)
if ($git) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $current = & $git config --global --get core.hooksPath 2>$null
    if ($current -eq (($Dest -replace '\\', '/') + '/hooks')) {
        if (Test-Path "$Dest\previous-hooksPath") {
            $prev = [IO.File]::ReadAllText("$Dest\previous-hooksPath").Trim()
            & $git config --global core.hooksPath $prev; Write-Host "OK  restored your previous git hooks folder: $prev"
        } else { & $git config --global --unset core.hooksPath; Write-Host 'OK  global git hooks removed' }
    }
    $ErrorActionPreference = $old
}

# 3. profile and .bashrc blocks
foreach ($f in @($PROFILE, (Join-Path $HOME '.bashrc'))) {
    if (-not (Test-Path $f)) { continue }
    $s = [IO.File]::ReadAllText($f)
    $n = [regex]::Replace($s, '(?s)\r?\n*' + [regex]::Escape($Begin) + '.*?' + [regex]::Escape($End) + '\r?\n?', "`n")
    if ($n -ne $s) { [IO.File]::WriteAllText($f, $n, $Utf8NoBom); Write-Host "OK  cleaned $f" }
}

# 4. PATH and files (reports and quarantined downloads are kept so you can review them)
$p = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($p) { [Environment]::SetEnvironmentVariable('Path', (($p -split ';') | Where-Object { $_ -and $_ -ne "$Dest\bin" }) -join ';', 'User') }
foreach ($x in @("$Dest\bin", "$Dest\hooks", "$Dest\checkrepo.py", "$Dest\kitlib.py", "$Dest\github_check.py", "$Dest\github-seen.json", "$Dest\autofix.py", "$Dest\feed.py", "$Dest\ed25519.py", "$Dest\indicators.signed", "$Dest\malware-paths.txt", "$Dest\daily-check.ps1", "$Dest\fingerprints.txt", "$Dest\hooks-enabled", "$Dest\previous-hooksPath")) {
    if (Test-Path $x) { Remove-Item -Recurse -Force $x }
}
if (Test-Path $Dest) {
    $left = Get-ChildItem $Dest
    if ($left) { Write-Host 'OK  removed the kit; kept for you to review or delete:'; $left | ForEach-Object { Write-Host "      $($_.FullName)" } }
    else { Remove-Item $Dest; Write-Host 'OK  removed %USERPROFILE%\.checkrepo' }
}
Write-Host "`nKept on purpose (good defaults). To revert: npm config delete ignore-scripts; remove the task/trust keys from your"
Write-Host 'editor settings.json (the original is saved next to it as settings.json.bak-checkrepo).'
Write-Host 'Open a new terminal for the change to take effect.'
