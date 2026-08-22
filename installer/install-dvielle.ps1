#Requires -Version 5.1
<#
.SYNOPSIS
    Install DVielle (DEEP VIGILLANCE) with Administrator privileges.
.DESCRIPTION
    Double-click Install-DVielle.bat — Windows UAC prompts for human approval,
    then installs to Program Files, sets up startup, and creates shortcuts.
#>
param(
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
$AppName = "DVielle"
$InstallDir = "$env:ProgramFiles\$AppName"
$DataDir = "$env:ProgramData\$AppName"
$TaskName = "DVielle"
$ShortcutName = "DVielle — Deep Vigilance"

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "ERROR: Run Install-DVielle.bat — it will request Administrator via UAC." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  ╔══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   DVIELLE — DEEP VIGILLANCE          ║" -ForegroundColor Cyan
Write-Host "  ║   Installing protection suite...     ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# 1. Copy application files
Write-Host "[1/7] Copying files to $InstallDir ..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$dirs = @("agent", "dvielle", "config", "scripts", "installer")
foreach ($d in $dirs) {
    $src = Join-Path $SourceRoot $d
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $InstallDir -Recurse -Force
    }
}
Copy-Item (Join-Path $SourceRoot "requirements.txt") $InstallDir -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $SourceRoot "pyproject.toml") $InstallDir -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $SourceRoot "README.md") $InstallDir -Force -ErrorAction SilentlyContinue

# 2. Data directory + config
Write-Host "[2/7] Setting up data directory ..."
New-Item -ItemType Directory -Force -Path "$DataDir\config" | Out-Null
New-Item -ItemType Directory -Force -Path "$DataDir\logs" | Out-Null
$configSrc = Join-Path $InstallDir "config"
if (Test-Path $configSrc) {
    Copy-Item "$configSrc\*" "$DataDir\config" -Recurse -Force
}

# 3. Python dependencies
Write-Host "[3/7] Installing Python dependencies ..."
$python = $null
foreach ($candidate in @("python", "python3", "py")) {
    try {
        $v = & $candidate --version 2>&1
        if ($LASTEXITCODE -eq 0) { $python = $candidate; break }
    } catch {}
}
if (-not $python) {
    Write-Host "ERROR: Python 3.12+ not found. Install from python.org first." -ForegroundColor Red
    exit 1
}
Push-Location $InstallDir
& $python -m pip install --upgrade pip -q
& $python -m pip install -r requirements.txt -q
& $python -m pip install customtkinter pillow pystray -q
Pop-Location

# 4. Defender exclusions
Write-Host "[4/7] Adding Defender exclusions ..."
try {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath $DataDir -ErrorAction SilentlyContinue
} catch {
    Write-Host "  (Defender exclusion skipped)" -ForegroundColor Yellow
}

# 5. Startup scheduled task — launches GUI at login
Write-Host "[5/7] Registering startup task ..."
$pythonw = & $python -c "import sys; print(sys.executable.replace('python.exe','pythonw.exe').replace('python3','pythonw'))"
if (-not (Test-Path $pythonw)) { $pythonw = & $python -c "import sys; print(sys.executable)" }

$action = New-ScheduledTaskAction -Execute $pythonw -Argument "-m dvielle" -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "DVielle Deep Vigilance Agent" | Out-Null

# 6. Start Menu + Desktop shortcuts
Write-Host "[6/7] Creating shortcuts ..."
$wsh = New-Object -ComObject WScript.Shell

$startMenu = [Environment]::GetFolderPath("Programs")
$lnk = $wsh.CreateShortcut("$startMenu\$ShortcutName.lnk")
$lnk.TargetPath = $pythonw
$lnk.Arguments = "-m dvielle"
$lnk.WorkingDirectory = $InstallDir
$lnk.Description = "DVielle — DEEP VIGILLANCE"
$lnk.Save()

$desktop = [Environment]::GetFolderPath("Desktop")
$lnk2 = $wsh.CreateShortcut("$desktop\$ShortcutName.lnk")
$lnk2.TargetPath = $pythonw
$lnk2.Arguments = "-m dvielle"
$lnk2.WorkingDirectory = $InstallDir
$lnk2.Save()

# Uninstaller shortcut
$uninstallLnk = $wsh.CreateShortcut("$startMenu\Uninstall DVielle.lnk")
$uninstallLnk.TargetPath = (Join-Path $InstallDir "installer\Uninstall-DVielle.bat")
$uninstallLnk.WorkingDirectory = (Join-Path $InstallDir "installer")
$uninstallLnk.Save()

# 7. Registry uninstall entry (Add/Remove Programs)
Write-Host "[7/7] Registering uninstaller ..."
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DVielle"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "DisplayName" -Value "DVielle — Deep Vigilance"
Set-ItemProperty -Path $regPath -Name "DisplayVersion" -Value "1.1.0"
Set-ItemProperty -Path $regPath -Name "Publisher" -Value "DVielle"
Set-ItemProperty -Path $regPath -Name "InstallLocation" -Value $InstallDir
Set-ItemProperty -Path $regPath -Name "UninstallString" -Value "`"$(Join-Path $InstallDir 'installer\Uninstall-DVielle.bat')`""
Set-ItemProperty -Path $regPath -Name "DisplayIcon" -Value $pythonw
Set-ItemProperty -Path $regPath -Name "NoModify" -Value 1

Write-Host ""
Write-Host "  ✓ DVIELLE installed successfully." -ForegroundColor Green
Write-Host "  ✓ Launch from Start Menu or Desktop shortcut." -ForegroundColor Green
Write-Host "  ✓ Minimize to system tray — stays vigilant in background." -ForegroundColor Green
Write-Host ""
Write-Host "  Optional: Run scripts\harden-once.ps1 as Admin for full privacy hardening." -ForegroundColor Cyan
Write-Host ""

# Launch GUI now
Start-Process $pythonw -ArgumentList "-m dvielle" -WorkingDirectory $InstallDir
