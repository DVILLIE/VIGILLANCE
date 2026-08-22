#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install Fortoro Agent as a scheduled task (runs every minute, monitor loop inside).
#>
param(
    [string]$InstallDir = "$env:ProgramFiles\FortoroAgent",
    [string]$PythonExe = "pythonw"
)

$ErrorActionPreference = "Stop"
$SourceRoot = Split-Path -Parent $PSScriptRoot

Write-Host "Installing Fortoro Agent to $InstallDir..."

# Copy files
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path "$SourceRoot\agent" -Destination "$InstallDir\agent" -Recurse -Force
Copy-Item -Path "$SourceRoot\config" -Destination "$InstallDir\config" -Recurse -Force
Copy-Item -Path "$SourceRoot\scripts" -Destination "$InstallDir\scripts" -Recurse -Force

# Data directory
$DataDir = "$env:ProgramData\FortoroAgent"
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
Copy-Item -Path "$InstallDir\config\*" -Destination "$DataDir\config" -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "$DataDir\config" | Out-Null
if (-not (Test-Path "$DataDir\config\config.yaml")) {
    Copy-Item -Path "$InstallDir\config\*" -Destination "$DataDir\config" -Force
}

# Defender exclusion
try {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath $DataDir -ErrorAction SilentlyContinue
    Write-Host "Defender exclusions added."
} catch {
    Write-Warning "Could not add Defender exclusion: $_"
}

# Scheduled task
$taskName = "FortoroAgent"
$action = New-ScheduledTaskAction -Execute $PythonExe -Argument "-m agent.main" -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Fortoro Windows Monitoring Agent" | Out-Null

Write-Host "Scheduled task '$taskName' registered (runs at startup)."
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. pip install -r requirements.txt"
Write-Host "  2. Run scripts\harden-once.ps1 once (as Administrator) for privacy hardening"
Write-Host "  3. Start the task: Start-ScheduledTask -TaskName FortoroAgent"
Write-Host "  4. After 7-day baseline, edit $DataDir\config\config.yaml to enable auto-actions"
