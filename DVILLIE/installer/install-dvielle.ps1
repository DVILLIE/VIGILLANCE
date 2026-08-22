#Requires -Version 5.1
<#
.SYNOPSIS
    Install DVielle to C:\DVILLIE with UAC elevation.
#>
param(
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$InstallDir = "C:\DVILLIE"
)

$ErrorActionPreference = "Stop"
$AppName = "DVielle"
$DataDir = "$InstallDir\data"
$ConfigDir = "$InstallDir\config"
$TaskName = "DVielle"
$ShortcutName = "DVielle — Deep Vigilance"

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "ERROR: Run Install-DVielle.bat — UAC will request Administrator." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  ╔══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   DVIELLE — DEEP VIGILLANCE          ║" -ForegroundColor Cyan
Write-Host "  ║   Installing to C:\DVILLIE             ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# 1. Create C:\DVILLIE and copy files
Write-Host "[1/8] Creating $InstallDir and copying files ..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
New-Item -ItemType Directory -Force -Path "$DataDir\logs" | Out-Null

$dirs = @("agent", "dvielle", "config", "scripts", "installer", "tests")
foreach ($d in $dirs) {
    $src = Join-Path $SourceRoot $d
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $InstallDir -Recurse -Force
    }
}
foreach ($f in @("requirements.txt", "pyproject.toml", "README.md")) {
    $src = Join-Path $SourceRoot $f
    if (Test-Path $src) { Copy-Item $src $InstallDir -Force }
}

# 2. Config into data + install config
Write-Host "[2/8] Setting up config at $ConfigDir ..."
Copy-Item "$InstallDir\config\*" $ConfigDir -Recurse -Force

# 3. Python
Write-Host "[3/8] Installing Python dependencies ..."
$python = $null
foreach ($candidate in @("python", "python3", "py")) {
    try {
        $null = & $candidate --version 2>&1
        if ($LASTEXITCODE -eq 0) { $python = $candidate; break }
    } catch {}
}
if (-not $python) {
    Write-Host "ERROR: Python 3.12+ required. Install from https://python.org" -ForegroundColor Red
    exit 1
}
Push-Location $InstallDir
& $python -m pip install --upgrade pip -q
& $python -m pip install -r requirements.txt -q
Pop-Location

# 4. Defender exclusions
Write-Host "[4/8] Defender exclusions ..."
try {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
} catch {}

# 5. Scheduled task — start GUI at login
Write-Host "[5/8] Registering startup task ..."
$pythonw = & $python -c "import sys; p=sys.executable; print(p.replace('python.exe','pythonw.exe'))"
if (-not (Test-Path $pythonw)) { $pythonw = & $python -c "import sys; print(sys.executable)" }

$action = New-ScheduledTaskAction -Execute $pythonw -Argument "-m dvielle" -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "DVielle Deep Vigilance" | Out-Null

# 6. Shortcuts
Write-Host "[6/8] Creating shortcuts ..."
$wsh = New-Object -ComObject WScript.Shell
$startMenu = [Environment]::GetFolderPath("Programs")
$desktop = [Environment]::GetFolderPath("Desktop")

foreach ($target in @($startMenu, $desktop)) {
    $lnk = $wsh.CreateShortcut("$target\$ShortcutName.lnk")
    $lnk.TargetPath = $pythonw
    $lnk.Arguments = "-m dvielle"
    $lnk.WorkingDirectory = $InstallDir
    $lnk.Description = "DVielle — DEEP VIGILLANCE"
    $lnk.Save()
}

$uninstallLnk = $wsh.CreateShortcut("$startMenu\Uninstall DVielle.lnk")
$uninstallLnk.TargetPath = "$InstallDir\installer\Uninstall-DVielle.bat"
$uninstallLnk.WorkingDirectory = "$InstallDir\installer"
$uninstallLnk.Save()

# 7. Registry uninstall entry
Write-Host "[7/8] Add/Remove Programs entry ..."
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DVielle"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "DisplayName" -Value "DVielle — Deep Vigilance"
Set-ItemProperty -Path $regPath -Name "DisplayVersion" -Value "1.2.0"
Set-ItemProperty -Path $regPath -Name "Publisher" -Value "DVielle"
Set-ItemProperty -Path $regPath -Name "InstallLocation" -Value $InstallDir
Set-ItemProperty -Path $regPath -Name "UninstallString" -Value "`"$InstallDir\installer\Uninstall-DVielle.bat`""

# 8. Smoke test
Write-Host "[8/8] Running smoke test ..."
Push-Location $InstallDir
& $python scripts\smoke_test.py
$smokeOk = $LASTEXITCODE
Pop-Location

if ($smokeOk -ne 0) {
    Write-Host "WARNING: Smoke test reported issues — check logs." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  ✓ DVIELLE installed to C:\DVILLIE" -ForegroundColor Green
Write-Host "  ✓ Data: C:\DVILLIE\data" -ForegroundColor Green
Write-Host "  ✓ Launch from Desktop or Start Menu" -ForegroundColor Green
Write-Host ""

Start-Process $pythonw -ArgumentList "-m dvielle" -WorkingDirectory $InstallDir
