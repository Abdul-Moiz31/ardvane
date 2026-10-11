# Ardvane - one-command, READ-ONLY scan of this Windows PC. BETA: not yet tested on real Windows.
# Nothing is installed, changed, deleted or run from your projects. No internet connection is needed.
#
#   powershell -ExecutionPolicy Bypass -File .\scan-my-machine.ps1               scan your user folder
#   powershell -ExecutionPolicy Bypass -File .\scan-my-machine.ps1 -Quick        machine checks only
#   powershell -ExecutionPolicy Bypass -File .\scan-my-machine.ps1 C:\code D:\work   scan these folders for projects
#
# Exit code: 0 clean, 1 malware evidence found, 2 only items worth a look.
# A copy of the report is saved as scan-report-YYYY-MM-DD-HHMM.txt in %USERPROFILE%\.checkrepo\reports\scans, where
# the dashboard lists it (or in $env:SCAN_REPORT_DIR). Never inside the app's own folder, which upgrades replace.
# For the dashboard: if $env:SCAN_EVENTS names a file, every result is also appended to it as
# tab-separated lines: TYPE <tab> message <tab> path  (TYPE: H section, D danger, W check, O ok, I info, P progress, R result)

param([switch]$Quick, [Parameter(ValueFromRemainingArguments = $true)][string[]]$Roots)

$Kit = $PSScriptRoot
$Checkrepo = Join-Path $Kit 'scanner\checkrepo.py'
$PkgCheck = Join-Path $Kit 'scanner\check-my-projects.py'
if (-not $Roots) { $Roots = @($HOME) }
$ReportDir = if ($env:SCAN_REPORT_DIR) { $env:SCAN_REPORT_DIR } else { Join-Path $HOME '.checkrepo\reports\scans' }
New-Item -ItemType Directory -Force -Path $ReportDir -ErrorAction SilentlyContinue | Out-Null
try { $probe = Join-Path $ReportDir '.write-test'; [IO.File]::WriteAllText($probe, ''); Remove-Item $probe -ErrorAction SilentlyContinue }
catch { $ReportDir = [IO.Path]::GetTempPath() }
$Protect = if ($env:ARDVANE_INSTALLED) { 'ardvane protect' } else { "powershell -ExecutionPolicy Bypass -File `"$Kit\windows\install.ps1`"" }
$Report = Join-Path $ReportDir ("scan-report-" + (Get-Date -Format 'yyyy-MM-dd-HHmm') + ".txt")
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
$lines = New-Object System.Collections.Generic.List[string]
$script:danger = 0; $script:warn = 0
function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c; $lines.Add($m) }
# machine-readable copy for the dashboard (no-op unless $env:SCAN_EVENTS is set)
function Ev($t, $m, $p = '') { if ($env:SCAN_EVENTS) { [IO.File]::AppendAllText($env:SCAN_EVENTS, "$t`t$(($m -replace "[`t`r`n]", ' '))`t$p`n", $Utf8NoBom) } }
function Bad($m, $p = '') { $script:danger++; Say "  [DANGER] $m" 'Red'; Ev 'D' $m $p }
function Chk($m, $p = '') { $script:warn++; Say "  [CHECK]  $m" 'Yellow'; Ev 'W' $m $p }
function Okay($m) { Say "  [OK]     $m" 'Green'; Ev 'O' $m }
function Info($m) { Say "  $m" 'DarkGray'; Ev 'I' $m }
function Head1($m) { Say ''; Say $m 'White'; Ev 'H' $m }
function Invoke-Native([scriptblock]$Block) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $Block } finally { $ErrorActionPreference = $old }
}
# Scan-Dir DIR LABEL: report checkrepo's verdict. No result (a crash, a hang) is "could not scan", never clean.
function Scan-Dir($dir, $label = '') {
    $line = [string](Invoke-Native { & $py.Exe @($py.Args) $Checkrepo --summary $dir 2>$null } | Select-Object -First 1)
    $code, $detail = $line -split ' ', 2
    switch ($code) {
        '0' { }
        '1' { Bad "INFECTED: $label$dir - $detail" $dir }
        '2' { Chk "worth a look: $label$dir - $detail" $dir }
        default { Chk "could not scan $dir ($detail) - run: checkrepo `"$dir`"" $dir }
    }
}

$py = $null
foreach ($c in 'py', 'python', 'python3') {
    $cmd = Get-Command $c -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cmd) { continue }
    $a = @(); if ($c -eq 'py') { $a = @('-3') }
    Invoke-Native { & $cmd.Source @a -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" 2>$null | Out-Null }
    if ($LASTEXITCODE -eq 0) { $py = @{ Exe = $cmd.Source; Args = $a }; break }
}
Say "Ardvane - machine scan  $(Get-Date -Format 'yyyy-MM-dd HH:mm') - read-only - Windows" 'White'
if (-not $py) { Say 'Python 3.8+ not found - project and package scans will be skipped (https://www.python.org/downloads/)' 'Yellow' }

# 1. known malware locations
Head1 '1. Known malware locations'; $n = $script:danger
foreach ($p in @("$env:LOCALAPPDATA\MicrosoftSystem64", "$env:LOCALAPPDATA\MicrosoftSystem64.exe", "$env:LOCALAPPDATA\Temp\tmp7A863DD1.tmp",
                 "$HOME\.node_modules", "$HOME\.n2", "$HOME\.n3", "$HOME\.npl", "$HOME\.pyp", "$HOME\.sysinfo", "$HOME\.pcl-data", "$HOME\.pcl-state")) {
    if (Test-Path $p) { Bad "found: $p" $p }
}
Get-ChildItem "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA" -Include 'SvcHostUpdate.py','SvcHostUpdate.js','MicrosoftCLROptimization.vbs','MicrosoftSystem64*' -Recurse -Depth 2 -ErrorAction SilentlyContinue |
    ForEach-Object { Bad "found: $($_.FullName)" $_.FullName }
if ($script:danger -eq $n) { Okay 'none' }

# 2. processes
Head1 '2. Running processes'; $n = $script:danger; $nw = $script:warn
foreach ($p in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -notmatch 'scan-my-machine' })) {
    $t = "$($p.ProcessId) $($p.Name) $($p.CommandLine)"; if ($t.Length -gt 180) { $t = $t.Substring(0, 180) }
    if ($p.Name -match 'MicrosoftSystem64|SvcHostUpdate' -or $p.CommandLine -match 'MicrosoftCLROptimization|\\\.node_modules\\|node(\.exe)?"?\s+\S*\.(eot|woff2?|ttf|otf|llf)(\s|$)') { Bad "process: $t" }
    elseif ($p.CommandLine -match 'node(\.exe)?"?\s+-e\s' -and $p.CommandLine -match 'https?://|eval|base64|Buffer\.from|atob') { Chk "inline node process fetching/decoding code: $t" }
}
if ($script:danger -eq $n -and $script:warn -eq $nw) { Okay 'nothing suspicious' }

# 3. startup items
Head1 '3. Programs that start automatically'; $n = $script:danger; $nw = $script:warn
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
    $acts = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' '
    if ("$($_.TaskName) $acts" -match 'MicrosoftCLROptimization|MicrosoftSystem64|SvcHostUpdate') { Bad "scheduled task: $($_.TaskPath)$($_.TaskName)" }
    elseif ($acts -match 'wscript|cscript|\.vbs|\\Temp\\|powershell.*-enc|node(\.exe)?\s|python(\.exe)?\s.*-c') { Chk "scheduled task runs a script - check you recognise it: $($_.TaskPath)$($_.TaskName) -> $acts" }
}
foreach ($dir in @([Environment]::GetFolderPath('Startup'))) {
    Get-ChildItem $dir -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Name -match 'MicrosoftCLROptimization|MicrosoftSystem64') { Bad "startup folder: $($_.FullName)" $_.FullName }
        elseif ($_.Extension -in '.vbs', '.js', '.bat', '.cmd', '.ps1') { Chk "startup folder script - check you recognise it: $($_.FullName)" $_.FullName }
    }
}
foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce') {
    $props = Get-ItemProperty $k -ErrorAction SilentlyContinue
    if ($props) { $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
        if ("$($_.Value)" -match 'MicrosoftSystem64|SvcHostUpdate|MicrosoftCLROptimization') { Bad "Run key: $($_.Name) = $($_.Value)" }
        elseif ("$($_.Value)" -match 'node|python|wscript|\.vbs|\.js\b|powershell.*-enc') { Chk "Run key runs a script - check you recognise it: $($_.Name) = $($_.Value)" }
    } }
}
if ($script:danger -eq $n -and $script:warn -eq $nw) { Okay 'nothing suspicious' }

# 4. PowerShell profile / hosts
Head1 '4. PowerShell profile and hosts file'; $n = $script:danger; $nw = $script:warn
foreach ($f in @($PROFILE, (Join-Path $HOME '.bashrc'))) {
    if (-not (Test-Path $f)) { continue }
    $txt = [IO.File]::ReadAllText($f)
    if ($txt -match 'MicrosoftSystem64|SvcHostUpdate|tg14xq') { Bad "malware reference in $f" $f }
    elseif ($txt -match 'iwr[^|#\r\n]*\|\s*iex|Invoke-WebRequest[^|#\r\n]*\|\s*Invoke-Expression|FromBase64String|curl[^|#\r\n]*\|\s*(ba)?sh') { Chk "$f runs downloaded/encoded code - check you added it" $f }
}
$hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' -and $_ -notmatch 'localhost' }
if ($hosts) { Chk "hosts file has custom entries (fine if you added them): $(($hosts | Select-Object -First 3) -join ' | ')" }
if ($script:danger -eq $n -and $script:warn -eq $nw) { Okay 'nothing suspicious' }

# 5. network
Head1 '5. Connections to known attacker servers'
$c2 = '^(166\.88\.(54\.158|134\.62|134\.75|134\.82|4\.2|73\.46)|198\.105\.127\.210|23\.27\.(202\.27|120\.142|13\.43|13\.135|20\.187)|154\.91\.0\.103|188\.43\.33\.249|202\.155\.8\.173|136\.0\.9\.8|179\.43\.166\.242|195\.201\.194\.107|193\.247\.144\.38|45\.137\.198\.133|181\.214\.149\.14[78]|91\.218\.183\.174|150\.251\.113\.223)$'
$hits = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -match $c2 }
if ($hits) { $hits | ForEach-Object { Bad "connection to $($_.RemoteAddress):$($_.RemotePort) from PID $($_.OwningProcess)" } } else { Okay 'none' }

# 6. editors
Head1 '6. Code editor settings and extensions'; $n = $script:danger; $nw = $script:warn
foreach ($ed in 'Code', 'Cursor', 'Windsurf') {
    $s = "$env:APPDATA\$ed\User"
    if (-not (Test-Path $s)) { continue }
    if ((Test-Path "$s\settings.json") -and (Select-String -Path "$s\settings.json" -Pattern '"task\.allowAutomaticTasks"\s*:\s*("on"|true)' -Quiet)) { Chk "${ed}: automatic tasks are ON - any folder you open can run code" }
    if ((Test-Path "$s\settings.json") -and (Select-String -Path "$s\settings.json" -Pattern '"security\.workspace\.trust\.enabled"\s*:\s*false' -Quiet)) { Chk "${ed}: Workspace Trust is OFF" }
    if ((Test-Path "$s\tasks.json") -and (Select-String -Path "$s\tasks.json" -Pattern 'folderOpen' -Quiet)) { Chk "${ed}: a global user task runs on every folder open - check $s\tasks.json" }
}
foreach ($e in "$HOME\.vscode\extensions", "$HOME\.cursor\extensions", "$HOME\.windsurf\extensions") {
    if (-not (Test-Path $e)) { continue }
    $all = @(Get-ChildItem $e -Directory -ErrorAction SilentlyContinue)
    $recent = ($all | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-14) } | ForEach-Object { $_.Name }) -join ' '
    Info "$(Split-Path (Split-Path $e -Parent) -Leaf) extensions: $($all.Count) installed$(if ($recent) { "; added/updated in the last 14 days: $recent" })"
}
if ($script:danger -eq $n -and $script:warn -eq $nw) { Okay 'safe settings' }

# 7. projects
Head1 '7. Your projects (every git repository + loose downloads)'
if ($Quick -or -not $py) { Info 'skipped' } else {
    $dn = $script:danger; $wn = $script:warn
    $repos = @(Get-ChildItem $Roots -Directory -Recurse -Depth 6 -Force -Filter '.git' -ErrorAction SilentlyContinue |
               Where-Object { $_.FullName -notmatch '\\(node_modules|AppData|\.cache|\.npm|\.cargo|\.rustup|\.gradle|\.m2)\\' })
    $i = 0
    foreach ($g in $repos) {
        $i++; $d = $g.Parent.FullName
        Write-Progress -Activity 'Scanning projects' -Status $d -PercentComplete ([int](100 * $i / [Math]::Max(1, $repos.Count))); Ev 'P' "$i $d"
        Scan-Dir $d
    }
    Write-Progress -Activity 'Scanning projects' -Completed
    foreach ($dl in "$HOME\Downloads", "$HOME\Desktop") {
        if (Test-Path $dl) { Scan-Dir $dl 'files in ' }
    }
    if ($repos.Count -eq 0) { Chk 'found 0 git repositories - if your projects live elsewhere, run: .\scan-my-machine.ps1 D:\path\to\projects' }
    elseif ($script:danger -eq $dn -and $script:warn -eq $wn) { Okay "$($repos.Count) repositories + Downloads/Desktop scanned - no malware" }
    else { Info "$($repos.Count) repositories scanned" }
}

# 8. packages
Head1 '8. Known malicious packages (npm / PyPI / Packagist, incl. global installs)'
if ($Quick -or -not $py) { Info 'skipped' } else {
    $out = Invoke-Native { & $py.Exe @($py.Args) $PkgCheck @Roots 2>$null }
    if ($LASTEXITCODE -eq 1) { $out | Where-Object { $_ -match '\[(npm|pypi|packagist)\]' } | ForEach-Object { Bad "malicious package: $($_.Trim())" } }
    else { Okay 'none of the known-malicious packages are used or installed' }
}

# 9. protections
Head1 '9. Built-in protections'
try { $mp = Get-MpComputerStatus -ErrorAction Stop; if ($mp.RealTimeProtectionEnabled) { Okay 'Microsoft Defender real-time protection on' } else { Chk 'Microsoft Defender real-time protection is OFF' } } catch { Info '(Defender status not available)' }
if ((Get-Command npm -ErrorAction SilentlyContinue) -and ((Invoke-Native { npm config get ignore-scripts }) -eq 'true')) { Okay 'npm install scripts blocked' }
else { Info "npm install scripts are allowed (the kit's installer blocks them)" }

# verdict
Say ''
if ($script:danger -gt 0) {
    Say "RESULT: INFECTED - $($script:danger) serious finding(s)." 'Red'
    Say 'Do NOT open the affected projects or run npm install in them. From another device if possible, follow:' 'Red'
    Say "  $Kit\docs\after-a-scan\if-danger-found.md   (cut off access first, then clean)"
    $code = 1
} elseif ($script:warn -gt 0) { Say "RESULT: no malware found - $($script:warn) item(s) worth a look (often harmless - read each line above)." 'Yellow'; $code = 2 }
else { Say 'RESULT: CLEAN - no signs of this malware.' 'Green'; $code = 0 }
Say "Protect yourself from now on:  $Protect"
[IO.File]::WriteAllLines($Report, $lines, $Utf8NoBom)
Say "Report saved: $Report" 'DarkGray'
Ev 'R' "$code" $Report
exit $code
