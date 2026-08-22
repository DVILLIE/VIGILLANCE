#Requires -Version 5.1
<#
.SYNOPSIS
    Uninstall DVielle — requires Administrator (UAC via Uninstall-DVielle.bat).
#>
param(
    [switch]$KeepData
)

$ErrorActionPreference = "SilentlyContinue"
$AppName = "DVielle"
$InstallDir = "$env:ProgramFiles\$AppName"
$DataDir = "$env:ProgramData\$AppName"
$TaskName = "DVielle"

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "ERROR: Run Uninstall-DVielle.bat — it will request Administrator via UAC." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  DVIELLE — Uninstalling..." -ForegroundColor Yellow
Write-Host ""

if (-not $KeepData) {
    $answer = Read-Host "Remove logs and database too? (y/N)"
    if ($answer -eq 'y' -or $answer -eq 'Y') {
        $KeepData = $false
    } else {
        $KeepData = $true
    }
}

# Stop running instances
Get-Process | Where-Object { $_.CommandLine -like '*dvielle*' -or $_.MainWindowTitle -like '*DVielle*' } | Stop-Process -Force -ErrorAction SilentlyContinue

# Remove scheduled task
Write-Host "[1/5] Removing startup task ..."
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false

# Remove shortcuts
Write-Host "[2/5] Removing shortcuts ..."
$startMenu = [Environment]::GetFolderPath("Programs")
$desktop = [Environment]::GetFolderPath("Desktop")
Remove-Item "$startMenu\DVielle — Deep Vigilance.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$startMenu\Uninstall DVielle.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$desktop\DVielle — Deep Vigilance.lnk" -Force -ErrorAction SilentlyContinue

# Remove registry uninstall entry
Write-Host "[3/5] Removing registry entry ..."
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DVielle" -Recurse -Force

# Remove program files
Write-Host "[4/5] Removing program files ..."
if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force
}

# Remove data (optional)
Write-Host "[5/5] Cleaning data ..."
if (-not $KeepData -and (Test-Path $DataDir)) {
    Remove-Item $DataDir -Recurse -Force
    Write-Host "  Data removed." -ForegroundColor Gray
} else {
    Write-Host "  Data kept at $DataDir" -ForegroundColor Gray
}

# Remove telemetry firewall rules (optional cleanup)
Get-NetFirewallRule -DisplayName "FortoroAgent-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "  ✓ DVIELLE uninstalled." -ForegroundColor Green
Write-Host ""
