#Requires -Version 5.1
param([switch]$KeepData, [string]$InstallDir = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
if (-not (Test-DvielleAdmin)) { throw 'Run Uninstall-DVielle.bat as Administrator.' }
$InstallDir = Resolve-DvielleRoot $InstallDir
$scriptRoot = Resolve-DvielleRoot (Split-Path -Parent $PSScriptRoot)
if ($InstallDir -ine $scriptRoot) { throw 'Uninstall must run from the exact installation being removed.' }
$metadata = Join-Path $InstallDir 'pyproject.toml'
if (-not (Test-Path -LiteralPath $metadata) -or
    (Get-Content -LiteralPath $metadata -Raw) -notmatch '(?m)^name\s*=\s*"dvielle"\s*$') {
    throw 'Target is not a validated DVielle installation.'
}
Disable-DvielleOwnedTasks $InstallDir
Stop-DvielleOwnedRuntime $InstallDir
foreach ($name in @('DVielle', 'DVielleGUI')) {
    $task = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
    if ($task) {
        if (-not (Test-DvielleTaskOwner $task $InstallDir)) { throw "Task $name belongs to another installation." }
        Unregister-ScheduledTask -TaskName $name -TaskPath '\' -Confirm:$false
    }
}
$shell = New-Object -ComObject WScript.Shell
foreach ($directory in @([Environment]::GetFolderPath('Programs'), [Environment]::GetFolderPath('Desktop'))) {
    foreach ($name in @('DVielle - Deep Vigilance.lnk', 'Uninstall DVielle.lnk')) {
        $path = Join-Path $directory $name
        if (Test-Path -LiteralPath $path) {
            $shortcut = $shell.CreateShortcut($path)
            if ($shortcut.WorkingDirectory -and
                ([IO.Path]::GetFullPath($shortcut.WorkingDirectory).TrimEnd('\') -ieq $InstallDir -or
                 [IO.Path]::GetFullPath($shortcut.WorkingDirectory).TrimEnd('\') -ieq (Join-Path $InstallDir 'installer'))) {
                Remove-Item -LiteralPath $path -Force
            }
        }
    }
}
$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DVielle'
if (Test-Path -LiteralPath $regPath) {
    $entry = Get-ItemProperty -LiteralPath $regPath
    if ($entry.InstallLocation -ieq $InstallDir) { Remove-Item -LiteralPath $regPath -Recurse -Force }
}
if (-not $KeepData) {
    $answer = Read-Host "Delete exactly $InstallDir including configuration, logs, and hardening backups? Type DELETE to confirm"
    if ($answer -ceq 'DELETE') {
        # Re-resolve immediately before deletion and reject nested junctions too.
        $deleteRoot = Resolve-DvielleRoot $InstallDir
        if ($deleteRoot -ine $scriptRoot) { throw 'Deletion target changed; stopping.' }
        Assert-DvielleTreeNoReparse $deleteRoot $deleteRoot
        if (@(Get-DvielleOwnedProcesses $deleteRoot).Count -gt 0) { throw 'DVielle restarted; deletion cancelled.' }
        Remove-Item -LiteralPath $deleteRoot -Recurse -Force
        Write-Host "Removed $deleteRoot."
    } else { Write-Host "Files retained at $InstallDir." }
}
Write-Host 'DVielle startup registration removed. Optional Windows hardening remains; restore it using its saved backup before deleting files.'
