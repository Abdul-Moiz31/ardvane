# Ardvane - daily security check for Windows (read-only). BETA: not yet tested on real Windows.
# Checks for the campaign's implants, persistence and C2 connections, scans your projects with checkrepo,
# verifies the kit's protections are still on, writes a report and shows a notification.
#   powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\.checkrepo\daily-check.ps1"
# Schedule it every morning: windows\install-routine.ps1
# Report: %USERPROFILE%\.checkrepo\reports\YYYY-MM-DD.txt
# Projects scanned: folders in %USERPROFILE%\.checkrepo\projects.txt (one per line, # for comments),
#                   default Documents, Desktop, Downloads, source\repos

$Dest = Join-Path $HOME '.checkrepo'
New-Item -ItemType Directory -Force -Path "$Dest\reports" | Out-Null
$Report = Join-Path "$Dest\reports" ((Get-Date -Format 'yyyy-MM-dd') + '.txt')
$lines = New-Object System.Collections.Generic.List[string]
$script:danger = 0; $script:warn = 0
function Add-Line($m) { $lines.Add($m) }
function Bad($m) { $script:danger++; $lines.Add("  [DANGER] $m") }
function Chk($m) { $script:warn++; $lines.Add("  [CHECK]  $m") }
function Invoke-Native([scriptblock]$Block) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $Block } finally { $ErrorActionPreference = $old }
}
# Scan-Dir DIR: report checkrepo's verdict. No result (a crash, a hang) is "could not scan", never clean.
function Scan-Dir($dir) {
    $line = [string](Invoke-Native { & $py.Exe @($py.Args) "$Dest\checkrepo.py" --summary $dir 2>$null } | Select-Object -First 1)
    $code, $detail = $line -split ' ', 2
    switch ($code) {
        '0' { }
        '1' { Bad "DANGER in ${dir}: $detail" }
        '2' { Chk "worth a look in ${dir}: $detail" }
        default { Chk "could not scan $dir ($detail) - run: checkrepo `"$dir`"" }
    }
}
Add-Line "Ardvane daily check - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"; Add-Line ''

# 1. known malware locations
Add-Line '1. Known malware locations'; $n = $script:danger
$paths = @("$env:LOCALAPPDATA\MicrosoftSystem64", "$env:LOCALAPPDATA\MicrosoftSystem64.exe", "$env:LOCALAPPDATA\Temp\tmp7A863DD1.tmp",
           "$HOME\.node_modules", "$HOME\.n2", "$HOME\.n3", "$HOME\.npl", "$HOME\.pyp", "$HOME\.sysinfo", "$HOME\.pcl-data", "$HOME\.pcl-state")
foreach ($p in $paths) { if (Test-Path $p) { Bad "found: $p" } }
Get-ChildItem "$env:TEMP" -Include 'SvcHostUpdate.py','SvcHostUpdate.js','MicrosoftCLROptimization.vbs' -Recurse -Depth 2 -ErrorAction SilentlyContinue |
    ForEach-Object { Bad "found: $($_.FullName)" }
if ($script:danger -eq $n) { Add-Line '  OK none' }

# 2. processes
Add-Line '2. Suspicious processes'; $n = $script:danger; $nw = $script:warn
$procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -notmatch 'daily-check' }
foreach ($p in $procs) {
    $t = "process: $($p.ProcessId) $($p.Name) $($p.CommandLine)"; if ($t.Length -gt 200) { $t = $t.Substring(0, 200) }
    if ($p.Name -match 'MicrosoftSystem64|SvcHostUpdate' -or $p.CommandLine -match 'MicrosoftCLROptimization|\\\.node_modules\\|node(\.exe)?"?\s+\S*\.(eot|woff2?|ttf|otf|llf)(\s|$)') { Bad $t }
    elseif ($p.CommandLine -match 'node(\.exe)?"?\s+-e\s' -and $p.CommandLine -match 'https?://|eval|base64|Buffer\.from|atob') { Chk "inline node $t" }
}
if ($script:danger -eq $n -and $script:warn -eq $nw) { Add-Line '  OK none' }

# 3. persistence (scheduled tasks / startup / Run keys)
Add-Line '3. Startup items'; $n = $script:warn; $nd = $script:danger
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -match 'MicrosoftCLROptimization|MicrosoftSystem64|SvcHost' -and $_.TaskPath -notlike '\Microsoft\*' } |
    ForEach-Object { Bad "scheduled task: $($_.TaskPath)$($_.TaskName)" }
$startup = [Environment]::GetFolderPath('Startup')
Get-ChildItem $startup -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) -or $_.Name -match 'MicrosoftCLROptimization' } |
    ForEach-Object { Chk "startup folder item: $($_.Name)" }
foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce') {
    $props = Get-ItemProperty $k -ErrorAction SilentlyContinue
    if ($props) { $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' -and "$($_.Value)" -match 'node|python|wscript|\.vbs|\.js|powershell.*-enc|MicrosoftSystem64' } |
        ForEach-Object { Chk "Run key $k : $($_.Name) = $($_.Value)" } }
}
if ($script:warn -eq $n -and $script:danger -eq $nd) { Add-Line '  OK nothing unusual' }

# 4. network
Add-Line '4. Connections to known attacker servers'
$c2 = '^(166\.88\.(54\.158|134\.62|134\.75|134\.82|4\.2|73\.46)|198\.105\.127\.210|23\.27\.(202\.27|120\.142|13\.43|13\.135|20\.187)|154\.91\.0\.103|188\.43\.33\.249|202\.155\.8\.173|136\.0\.9\.8|179\.43\.166\.242|195\.201\.194\.107|193\.247\.144\.38|45\.137\.198\.133|181\.214\.149\.14[78]|91\.218\.183\.174|150\.251\.113\.223)$'
$hits = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -match $c2 }
if ($hits) { $hits | ForEach-Object { Bad "connection to $($_.RemoteAddress):$($_.RemotePort) from PID $($_.OwningProcess)" } } else { Add-Line '  OK none' }

# 5. projects
Add-Line '5. Projects (checkrepo)'
$py = $null
foreach ($c in 'py', 'python', 'python3') {
    $cmd = Get-Command $c -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cmd) { continue }
    $a = @(); if ($c -eq 'py') { $a = @('-3') }
    Invoke-Native { & $cmd.Source @a -c 'import sys' 2>$null | Out-Null }
    if ($LASTEXITCODE -eq 0) { $py = @{ Exe = $cmd.Source; Args = $a }; break }
}
if ($py -and (Test-Path "$Dest\checkrepo.py")) {
    if (Test-Path "$Dest\projects.txt") {
        $cand = Get-Content "$Dest\projects.txt" | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ } |
                ForEach-Object { $_ -replace '^~', $HOME }
    } else { $cand = @("$HOME\Documents", "$HOME\Desktop", "$HOME\Downloads", "$HOME\source\repos") }
    $roots = @()
    foreach ($d in $cand) {
        if (Test-Path $d) { $roots += $d } elseif (Test-Path "$Dest\projects.txt") { Chk "folder in projects.txt not found: $d" }
    }
    $repos = @()
    if ($roots.Count -gt 0) {
        $repos = @(Get-ChildItem $roots -Directory -Recurse -Depth 4 -Force -Filter '.git' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\\node_modules\\' })
    }
    foreach ($g in $repos) { Scan-Dir $g.Parent.FullName }
    if (Test-Path "$HOME\Downloads") { Scan-Dir "$HOME\Downloads" }   # loose downloads, e.g. a coding test
    if ($repos.Count -eq 0) { Chk 'scanned 0 repositories - nothing was checked. List your project folders in %USERPROFILE%\.checkrepo\projects.txt' }
    else { Add-Line "  scanned $($repos.Count) repositories" }
} else { Chk 'checkrepo is not installed - run windows\install.ps1' }

# 6. protections
Add-Line '6. Protections'; $n = $script:danger; $nw = $script:warn
$hp = Invoke-Native { git config --global --get core.hooksPath 2>$null }
if ($hp -ne (($Dest -replace '\\', '/') + '/hooks')) {
    if (Test-Path "$Dest\hooks-enabled") { Bad "TAMPERED: global git hooks were turned off (core.hooksPath='$hp') - re-run the installer" }
    else { Chk 'git hooks are not enabled (you kept your own hooks folder) - clones/pushes are not scanned automatically' }
}
if (Test-Path "$Dest\fingerprints.txt") {
    foreach ($l in Get-Content "$Dest\fingerprints.txt") {
        $sum, $file = $l -split ' ', 2
        if ($file -and (Test-Path $file) -and ((Get-FileHash -Algorithm SHA256 $file).Hash.ToLower() -ne $sum)) { Bad "TAMPERED: $file was modified" }
    }
}
if ((Get-Command npm -ErrorAction SilentlyContinue) -and ((Invoke-Native { npm config get ignore-scripts }) -ne 'true')) { Chk 'npm ignore-scripts is off' }
$vs = "$env:APPDATA\Code\User\settings.json"
if ((Test-Path $vs) -and -not (Select-String -Path $vs -Pattern '"task.allowAutomaticTasks"\s*:\s*"off"' -Quiet)) { Chk 'VS Code automatic tasks are not off' }
Get-ChildItem "$HOME\.vscode\extensions", "$HOME\.cursor\extensions" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } |
    ForEach-Object { Chk "editor extension installed/updated in last 24h: $($_.Name) - make sure you trust its publisher" }
if ($script:danger -eq $n -and $script:warn -eq $nw) { Add-Line '  OK intact' }

# 7. GitHub account (opt-in, set in the dashboard's Settings)
$ghUser = ''
try { $st = Get-Content "$Dest\settings.json" -Raw -ErrorAction Stop | ConvertFrom-Json; if ($st.github_enabled) { $ghUser = "$($st.github_user)" } } catch { }
if ($py -and $ghUser -and (Test-Path "$Dest\github_check.py")) {
    Add-Line "7. GitHub account @$ghUser"
    $json = Invoke-Native { & $py.Exe @($py.Args) "$Dest\github_check.py" $ghUser --json 2>$null }
    $res = $null; try { $res = ($json -join "`n") | ConvertFrom-Json } catch { }
    if (-not $res) { Chk 'the GitHub check could not run' }
    elseif ($res.error) { Chk "the GitHub check could not run: $($res.error)" }
    else {
        foreach ($f in $res.findings) { if ($f[0] -eq 'DANGER') { Bad "$($f[1]): $($f[2])" } else { Chk "$($f[1]): $($f[2])" } }
        if (-not $res.findings) { Add-Line "  OK $($res.repos) repositories, $(@($res.scanned).Count) recently pushed scanned - no malware" }
    }
}

# 8. automatic fixes (only in "Automatic" mode)
$fixMode = 'ask'
try { $st2 = Get-Content "$Dest\settings.json" -Raw -ErrorAction Stop | ConvertFrom-Json; if ($st2.autofix) { $fixMode = "$($st2.autofix)" } } catch { }
if ($py -and $fixMode -eq 'auto' -and (Test-Path "$Dest\autofix.py")) {
    $fixed = Invoke-Native { & $py.Exe @($py.Args) "$Dest\autofix.py" auto 2>&1 }
    if ($fixed) {
        Add-Line '8. Automatic fixes'
        $fixed | ForEach-Object { Add-Line "$_" }
        if ($script:danger -gt 0) { Add-Line '  Files were removed from this computer, but anything stolen before is still stolen - finish the recovery checklist.' }
    }
}

# verdict
if ($script:danger -gt 0) { $verdict = "ACTION NEEDED - $($script:danger) serious finding(s). Don't open affected projects; see docs\after-a-scan\if-danger-found.md" }
elseif ($script:warn -gt 0) { $verdict = "Clean, $($script:warn) item(s) worth a look" }
else { $verdict = 'ALL CLEAN - no signs of malware, protections intact' }
$lines.Insert(0, "VERDICT: $verdict`n")
[IO.File]::WriteAllLines($Report, $lines, (New-Object System.Text.UTF8Encoding $false))
$lines | ForEach-Object { Write-Host $_ }
if (-not $env:CHECKREPO_NO_NOTIFY) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $ni = New-Object System.Windows.Forms.NotifyIcon
        $ni.Icon = [System.Drawing.SystemIcons]::Shield; $ni.Visible = $true
        $ni.ShowBalloonTip(10000, 'Daily security check', $verdict, $(if ($script:danger) { 'Error' } else { 'Info' }))
        Start-Sleep -Seconds 6; $ni.Dispose()
    } catch { }
}
if ($script:danger -gt 0) { exit 1 } else { exit 0 }
