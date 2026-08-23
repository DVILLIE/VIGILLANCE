#Requires -Version 5.1
param([switch]$KeepData)

$InstallDir = "C:\DVILLIE"
$DataDir = "$InstallDir\data"
$TaskName = "DVielle"
$TaskNameGui = "DVielleGUI"
$ShortcutName = "DVielle - Deep Vigilance"

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "ERROR: Run Uninstall-DVielle.bat for UAC elevation." -ForegroundColor Red
    exit 1
}

Write-Host "Uninstalling DVielle from $InstallDir ..." -ForegroundColor Yellow

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskNameGui -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "FortoroAgent" -Confirm:$false -ErrorAction SilentlyContinue

$startMenu = [Environment]::GetFolderPath("Programs")
$desktop = [Environment]::GetFolderPath("Desktop")
Remove-Item "$startMenu\$ShortcutName.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$startMenu\Uninstall DVielle.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$desktop\$ShortcutName.lnk" -Force -ErrorAction SilentlyContinue
# Legacy fancy-dash shortcut name
Remove-Item "$startMenu\DVielle - Deep Vigilance.lnk" -Force -ErrorAction SilentlyContinue

Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DVielle" -Recurse -Force -ErrorAction SilentlyContinue

if (-not $KeepData) {
    $answer = Read-Host "Delete C:\DVILLIE completely including logs? (y/N)"
    if ($answer -eq 'y' -or $answer -eq 'Y') {
        if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
        Write-Host "Removed $InstallDir" -ForegroundColor Gray
    } else {
        Write-Host "Kept data at $DataDir" -ForegroundColor Gray
    }
}

Write-Host "DVielle uninstalled." -ForegroundColor Green
