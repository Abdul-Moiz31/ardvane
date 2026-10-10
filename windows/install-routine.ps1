# Ardvane - schedule the daily check on Windows with Task Scheduler (BETA).
# Runs every day at 09:00 (or as soon as possible if the PC was off). Also records fingerprints of the kit's
# files so the check can tell you if malware tampers with them.
#   powershell -ExecutionPolicy Bypass -File .\windows\install-routine.ps1 [-At "08:30"]
#   powershell -ExecutionPolicy Bypass -File .\windows\install-routine.ps1 -Remove

param([string]$At = '09:00', [switch]$Remove)
$Dest = Join-Path $HOME '.checkrepo'; $Name = 'polinrider-survival-kit daily check'

if ($Remove) { Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction SilentlyContinue; Write-Host 'OK  daily check removed'; exit 0 }
if ($At -notmatch '^([01]?\d|2[0-3]):[0-5]\d$') { Write-Host "Invalid time '$At'. Use HH:MM, e.g. -At 08:30" -ForegroundColor Red; exit 3 }
if (-not (Test-Path "$Dest\checkrepo.py")) { Write-Host 'Install the scanner first: windows\install.ps1' -ForegroundColor Red; exit 1 }

Copy-Item "$PSScriptRoot\daily-check.ps1" "$Dest\daily-check.ps1" -Force
Unblock-File "$Dest\daily-check.ps1" -ErrorAction SilentlyContinue
# fingerprint every file git or the routine will run (Windows hooks are copies, so each one is listed)
$files = @("$Dest\checkrepo.py", "$Dest\kitlib.py", "$Dest\github_check.py", "$Dest\autofix.py", "$Dest\malware-paths.txt", "$Dest\bin\safeclone.ps1", "$Dest\bin\git-safeclone", "$Dest\daily-check.ps1") +
         @(Get-ChildItem "$Dest\hooks" -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
$fp = foreach ($f in $files) { if (Test-Path $f) { "$((Get-FileHash -Algorithm SHA256 $f).Hash.ToLower()) $f" } }
[IO.File]::WriteAllLines("$Dest\fingerprints.txt", [string[]]$fp, (New-Object System.Text.UTF8Encoding $false))

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Dest\daily-check.ps1`""
$trigger = New-ScheduledTaskTrigger -Daily -At $At
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries
Register-ScheduledTask -TaskName $Name -Action $action -Trigger $trigger -Settings $settings -Description 'Read-only check for PolinRider / Contagious Interview malware' -Force | Out-Null
Write-Host "OK  daily check scheduled at $At every day" -ForegroundColor Green
Write-Host "    Run it now:  powershell -ExecutionPolicy Bypass -File `"$Dest\daily-check.ps1`""
Write-Host "    Reports:     $Dest\reports\"
Write-Host "    Remove:      .\windows\install-routine.ps1 -Remove"
