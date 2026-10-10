# polinrider-survival-kit - safe clone for Windows PowerShell (BETA: not yet tested on real Windows).
# Clones WITHOUT writing project files, scans a private copy, and only writes the files if clean.
# If malware is found, no project files are written and the download goes to the Recycle Bin.
# Called by the `git` function the installer adds to your PowerShell profile:
#     & safeclone.ps1 <clone arguments...>
# Plain $args on purpose (no param block), so options like -b / -c / -o reach git untouched.
# Bypass once (only if you are sure):  git.exe clone ...

$CloneArgs = [string[]]$args
$Checkrepo = Join-Path $HOME '.checkrepo\checkrepo.py'
$GitExe = (Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source

function Invoke-Native([scriptblock]$Block) {
    # run a native command without letting its stderr turn into a terminating PowerShell error
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $Block } finally { $ErrorActionPreference = $old }
}

function Find-Python {
    foreach ($c in @('py', 'python', 'python3')) {
        $cmd = Get-Command $c -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $cmd) { continue }
        $pyArgs = @(); if ($c -eq 'py') { $pyArgs = @('-3') }
        Invoke-Native { & $cmd.Source @pyArgs -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" 2>$null | Out-Null }
        if ($LASTEXITCODE -eq 0) { return @{ Exe = $cmd.Source; Args = $pyArgs } }   # skips the Microsoft Store stub
    }
    return $null
}

# --- work out the target folder from the clone arguments ---
$takesValue = @('-b','--branch','-o','--origin','-c','--config','--depth','--reference','--reference-if-able',
                '--separate-git-dir','-j','--jobs','--filter','--template','-u','--upload-pack','--shallow-since',
                '--shallow-exclude','--server-option','--bundle-uri','--ref-format')
$pos = @(); $recurse = $false; $passthrough = $false
for ($i = 0; $i -lt $CloneArgs.Count; $i++) {
    $a = $CloneArgs[$i]
    if ($a -in @('--recursive', '--recurse-submodules') -or $a -like '--recurse-submodules=*') { $recurse = $true; continue }
    if ($a -in @('--bare', '--mirror', '-n', '--no-checkout')) { $passthrough = $true; continue }
    if ($a -eq '--') { if ($i + 1 -lt $CloneArgs.Count) { $pos += $CloneArgs[($i + 1)..($CloneArgs.Count - 1)] }; break }
    if ($a -like '--*=*') { continue }
    if ($a.StartsWith('-')) { if ($a -in $takesValue) { $i++ }; continue }
    $pos += $a
}
$url = $pos | Select-Object -First 1
$dest = $null
if ($pos.Count -ge 2) { $dest = $pos[1] } elseif ($url) { $dest = ($url.TrimEnd('/') -split '[/:\\]')[-1] -replace '\.git$', '' }
$py = Find-Python
if ($passthrough -or -not $GitExe -or -not $py -or -not (Test-Path $Checkrepo) -or -not $url -or -not $dest -or (Test-Path $dest)) {
    # nothing to protect (bare / no-checkout) or can't run safely - normal clone; the post-checkout git hook still scans
    & $GitExe clone @CloneArgs; exit $LASTEXITCODE
}

function Block-Clone($why) {
    try {
        Add-Type -AssemblyName Microsoft.VisualBasic
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory((Resolve-Path $dest).Path, 'OnlyErrorDialogs', 'SendToRecycleBin')
        $where = 'the Recycle Bin'
    } catch {
        $q = Join-Path $HOME '.checkrepo\quarantine'; New-Item -ItemType Directory -Force -Path $q | Out-Null
        Move-Item $dest (Join-Path $q ("BLOCKED-" + (Split-Path $dest -Leaf) + "-" + (Get-Date -Format 'yyyyMMdd-HHmmss')))
        $where = $q
    }
    Write-Host "CLONE BLOCKED - malware found. $why The download was moved to $where." -ForegroundColor Red
    Write-Host ("   If you are 100% sure this is a false alarm: git.exe clone " + (($CloneArgs | ForEach-Object { if ($_ -match '\s') { "'$_'" } else { $_ } }) -join ' '))
    exit 1
}

# --- 1. clone without checking out any files ---
& $GitExe clone --no-checkout @CloneArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Invoke-Native { & $GitExe -C $dest rev-parse -q --verify HEAD 2>$null | Out-Null }
if ($LASTEXITCODE -ne 0) { Write-Host '(empty repository)'; exit 0 }

# --- 2. write the files into a private temp folder, scan, delete the temp folder ---
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("safeclone-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    # (not `git archive`: a repo could hide files from it via .gitattributes export-ignore)
    Invoke-Native { & $GitExe -C $dest -c core.fsmonitor=false "--work-tree=$tmp" checkout -q -f HEAD -- . 2>$null | Out-Null }
    $out = Invoke-Native { & $py.Exe @($py.Args) $Checkrepo --quiet $tmp }
    $rc = $LASTEXITCODE
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
if ($out) { ($out -join "`n").Replace($tmp, "$dest (not unpacked)") | Write-Host }
if ($rc -eq 1) { Block-Clone 'No project files were written.' }

# --- 3. clean -> write the files; with submodules, scan again after they are fetched ---
& $GitExe -C $dest reset -q --hard HEAD
if ($recurse) {
    & $GitExe -C $dest submodule update --init --recursive
    $out2 = Invoke-Native { & $py.Exe @($py.Args) $Checkrepo --quiet --include-deps $dest }
    $src = $LASTEXITCODE
    if ($out2) { $out2 | Write-Host }
    if ($src -eq 1) { Block-Clone 'A submodule contains malware.' }
    if ($src -eq 2) { $rc = 2 }
}
if ($rc -eq 2) { Write-Host '(cloned, but see the warnings above)' -ForegroundColor Yellow }
exit 0
