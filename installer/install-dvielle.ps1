#Requires -Version 5.1
<#
.SYNOPSIS
    Install DVielle to C:\DVILLIE with UAC elevation.
    Registers headless vigilance agent at logon + GUI shortcut/task.
#>
param(
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$InstallDir = "C:\DVILLIE"
)

$ErrorActionPreference = "Stop"
$DataDir = "$InstallDir\data"
$ConfigDir = "$InstallDir\config"
$TaskName = "DVielle"
$TaskNameGui = "DVielleGUI"
$ShortcutName = "DVielle - Deep Vigilance"

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-Python312 {
    # Prefer Python 3.12 for DVielle
    try {
        $exe = & py -3.12 -c "import sys; print(sys.executable)" 2>$null
        if ($exe -and (Test-Path $exe.Trim())) { return $exe.Trim() }
    } catch {}
    foreach ($name in @("python3.12", "python")) {
        try {
            $exe = & $name -c "import sys; print(sys.executable)" 2>$null
            if ($exe -and (Test-Path $exe.Trim())) {
                $ver = & $name -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
                if ($ver -and [version]$ver -ge [version]"3.12") { return $exe.Trim() }
            }
        } catch {}
    }
    return $null
}

if (-not (Test-IsAdmin)) {
    Write-Host "ERROR: Run Install-DVielle.bat - UAC will request Administrator." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  DVIELLE - DEEP VIGILLANCE  ->  C:\DVILLIE" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/9] Creating $InstallDir and copying files ..."
New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir, $ConfigDir, "$DataDir\logs" | Out-Null

# Same folder = already living at C:\DVILLIE (dev / laptop checkout). Skip self-copy.
$srcRoot = (Resolve-Path $SourceRoot).Path.TrimEnd('\')
$dstRoot = (Resolve-Path $InstallDir).Path.TrimEnd('\')
if ($srcRoot -ieq $dstRoot) {
    Write-Host "  Source is already $InstallDir - skip file copy."
} else {
    $dirs = @("agent", "dvielle", "config", "scripts", "installer", "tests", "docs", "assets")
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
}

$nested = Join-Path $InstallDir "DVILLIE"
if (Test-Path $nested) {
    Remove-Item $nested -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "[2/9] Setting up config ..."
if (-not (Test-Path "$ConfigDir\config.yaml")) {
    Write-Host "ERROR: Missing $ConfigDir\config.yaml" -ForegroundColor Red
    exit 1
}
Write-Host "  Config OK: $ConfigDir"

Write-Host "[3/9] Installing Python dependencies (prefer 3.12) ..."
$pythonExe = Resolve-Python312
if (-not $pythonExe) {
    Write-Host "ERROR: Python 3.12+ required. Install 3.12 from https://python.org" -ForegroundColor Red
    exit 1
}
Write-Host "  Using: $pythonExe"
$pythonw = $pythonExe -replace 'python\.exe$', 'pythonw.exe'
if (-not (Test-Path $pythonw)) { $pythonw = $pythonExe }

Push-Location $InstallDir
& $pythonExe -m pip install --upgrade pip -q
& $pythonExe -m pip install -r requirements.txt -q
Pop-Location

Write-Host "[4/9] Defender exclusions ..."
try { Add-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue } catch {}

Write-Host "[5/9] Enabling logon-failure audit (Event 4625) ..."
try {
    & auditpol.exe /set /subcategory:"Logon" /failure:enable | Out-Null
    Write-Host "  auditpol Logon failure = enabled"
} catch {
    Write-Host "  WARNING: auditpol failed - attacks module may see no events." -ForegroundColor Yellow
}

Write-Host "[6/9] Registering startup tasks (headless agent + GUI) ..."
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$trigger = New-ScheduledTaskTrigger -AtLogOn

$actionAgent = New-ScheduledTaskAction -Execute $pythonw -Argument "-m agent.main" -WorkingDirectory $InstallDir
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $actionAgent -Trigger $trigger -Settings $settings -Principal $principal -Description "DVielle Deep Vigilance headless agent" | Out-Null

# GUI is optional via shortcut only — do not auto-open a second window at logon
Unregister-ScheduledTask -TaskName $TaskNameGui -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "FortoroAgent" -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "[7/9] Creating shortcuts ..."
$wsh = New-Object -ComObject WScript.Shell
$startMenu = [Environment]::GetFolderPath("Programs")
$desktop = [Environment]::GetFolderPath("Desktop")
foreach ($target in @($startMenu, $desktop)) {
    $lnk = $wsh.CreateShortcut("$target\$ShortcutName.lnk")
    # pythonw = GUI only, no black console window
    $lnk.TargetPath = $pythonw
    $lnk.Arguments = "-m dvielle"
    $lnk.WorkingDirectory = $InstallDir
    $lnk.Description = "DVielle - DEEP VIGILLANCE"
    $ico = Join-Path $InstallDir "assets\brand\dvielle.ico"
    if (Test-Path $ico) { $lnk.IconLocation = "$ico,0" }
    $lnk.Save()
}
$uninstallLnk = $wsh.CreateShortcut("$startMenu\Uninstall DVielle.lnk")
$uninstallLnk.TargetPath = "$InstallDir\installer\Uninstall-DVielle.bat"
$uninstallLnk.WorkingDirectory = "$InstallDir\installer"
$uninstallLnk.Save()

Write-Host "[8/9] Add/Remove Programs entry ..."
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DVielle"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "DisplayName" -Value "DVielle - Deep Vigilance"
Set-ItemProperty -Path $regPath -Name "DisplayVersion" -Value "1.4.0"
Set-ItemProperty -Path $regPath -Name "Publisher" -Value "DVielle"
Set-ItemProperty -Path $regPath -Name "InstallLocation" -Value $InstallDir
Set-ItemProperty -Path $regPath -Name "UninstallString" -Value "`"$InstallDir\installer\Uninstall-DVielle.bat`""

Write-Host "[9/9] Running smoke test ..."
Push-Location $InstallDir
& $pythonExe scripts\smoke_test.py
$smokeOk = $LASTEXITCODE
Pop-Location
if ($smokeOk -ne 0) {
    Write-Host "WARNING: Smoke test reported issues - check logs." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Installed to C:\DVILLIE" -ForegroundColor Green
Write-Host "  Headless task: $TaskName | GUI task: $TaskNameGui" -ForegroundColor Green
Write-Host "  Optional harden: scripts\harden-once.ps1 (Admin)" -ForegroundColor Green
Write-Host ""

Start-Process $pythonw -ArgumentList "-m agent.main" -WorkingDirectory $InstallDir
