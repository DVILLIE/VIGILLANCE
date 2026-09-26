#Requires -Version 5.1
<# Install with the vetted Python 3.12 runtime. This script changes the system only when run explicitly. #>
param(
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$InstallDir = 'C:\DVILLIE'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

function Resolve-Python312 {
    foreach ($candidate in @(@('py', '-3.12'), @('python3.12'), @('python'))) {
        try {
            $program = $candidate[0]
            $prefix = @($candidate | Select-Object -Skip 1)
            $result = & $program @prefix -c 'import sys; print(sys.executable); sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)' 2>$null
            if ($LASTEXITCODE -eq 0 -and $result -and (Test-Path -LiteralPath ([string]$result).Trim())) {
                return ([string]$result).Trim()
            }
        } catch { continue }
    }
    throw 'Python 3.12 is required. Install the free Windows Python 3.12 distribution from python.org.'
}

if (-not (Test-DvielleAdmin)) { throw 'Run installer\Install-DVielle.bat as Administrator.' }
$srcRoot = Resolve-DvielleRoot $SourceRoot
$InstallDir = Resolve-DvielleRoot $InstallDir
foreach ($required in @('agent\main.py', 'dvielle\__main__.py', 'pyproject.toml', 'config\config.yaml', 'scripts\smoke_test.py', 'scripts\verify_runtime.py')) {
    if (-not (Test-Path -LiteralPath (Join-Path $srcRoot $required) -PathType Leaf)) {
        throw "Invalid source tree: missing $required. Nothing installed."
    }
}
$metadata = Get-Content -LiteralPath (Join-Path $srcRoot 'pyproject.toml') -Raw
if ($metadata -notmatch '(?m)^name\s*=\s*"dvielle"\s*$') { throw 'Source metadata is not the DVielle project.' }
if ($InstallDir.StartsWith($srcRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
    $srcRoot.StartsWith($InstallDir + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Source and destination may be identical, but neither may be nested inside the other.'
}
$basePython = Resolve-Python312
Write-Host "Installing DVielle to $InstallDir with Python 3.12."

# Disable owned startup triggers before quiescing the runtime, so it cannot restart during copying.
foreach ($relative in @('agent', 'dvielle', 'scripts', 'installer', 'tests', 'docs', 'assets', 'config', 'requirements.txt', 'pyproject.toml', 'README.md')) {
    Assert-DvielleTreeNoReparse $srcRoot (Join-Path $srcRoot $relative)
    Assert-DvielleTreeNoReparse $InstallDir (Join-Path $InstallDir $relative)
}
foreach ($relative in @('data', '.venv')) { Assert-DvielleTreeNoReparse $InstallDir (Join-Path $InstallDir $relative) }
Disable-DvielleOwnedTasks $InstallDir
if (Test-Path -LiteralPath (Join-Path $InstallDir 'agent\main.py')) { Stop-DvielleOwnedRuntime $InstallDir }

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
if ($srcRoot -ine $InstallDir) {
    foreach ($folder in @('agent', 'dvielle', 'scripts', 'installer', 'tests', 'docs', 'assets')) {
        $source = Join-Path $srcRoot $folder
        if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination $InstallDir -Recurse -Force }
    }
    foreach ($file in @('requirements.txt', 'pyproject.toml', 'README.md')) {
        Copy-Item -LiteralPath (Join-Path $srcRoot $file) -Destination $InstallDir -Force
    }
    # Preserve all existing user configuration; copy only missing defaults.
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $srcRoot 'config') -File -Recurse) {
        $relative = $file.FullName.Substring($srcRoot.Length + 1)
        $target = Join-Path $InstallDir $relative
        if (-not (Test-Path -LiteralPath $target)) {
            New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
            Copy-Item -LiteralPath $file.FullName -Destination $target
        }
    }
}
New-Item -ItemType Directory -Path (Join-Path $InstallDir 'data\logs') -Force | Out-Null
$venv = Join-Path $InstallDir '.venv'
$python = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { Invoke-DvielleNative $basePython @('-m', 'venv', $venv) }
Invoke-DvielleNative $python @('-c', 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)')
$pythonw = Join-Path $venv 'Scripts\pythonw.exe'
if (-not (Test-Path -LiteralPath $pythonw)) { throw 'The Python 3.12 environment lacks pythonw.exe.' }
Push-Location $InstallDir
try {
    Invoke-DvielleNative $python @('-m', 'pip', 'install', '-e', '.[windows,chat]')
    Invoke-DvielleNative $python @('-m', 'pip', 'check')
    # No collector execution, persistence, cloud lookup, or machine mutation in this check.
    Invoke-DvielleNative $python @('scripts\smoke_test.py')
} finally { Pop-Location }

# GUIDs avoid localized Logon and Credential Validation display names (4625 and 4776).
foreach ($subcategory in @('{0CCE9215-69AE-11D9-BED3-505054503030}', '{0CCE923F-69AE-11D9-BED3-505054503030}')) {
    Invoke-DvielleNative 'auditpol.exe' @('/set', ('/subcategory:' + $subcategory), '/failure:enable')
    Invoke-DvielleNative 'auditpol.exe' @('/get', ('/subcategory:' + $subcategory))
}

# All prerequisites have passed before task activation.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$settings = New-ScheduledTaskSettingsSet -Disable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
$settings.ExecutionTimeLimit = 'PT0S'
# Resident task runs Limited. Highest is not the default.
# Elevation is only the explicit installer/uninstall path in elevate.ps1 (RunAs).
$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
$action = New-ScheduledTaskAction -Execute $pythonw -Argument '-m agent.main' -WorkingDirectory $InstallDir
Register-ScheduledTask -TaskName 'DVielle' -TaskPath '\' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description 'DVielle resident monitor' -Force | Out-Null
$registered = Get-ScheduledTask -TaskName 'DVielle' -TaskPath '\'
if ($registered.Settings.ExecutionTimeLimit -ne 'PT0S' -or $registered.Settings.MultipleInstances -ne 'IgnoreNew' -or
    $registered.Settings.RestartCount -ne 3 -or
    -not (Test-DvielleTaskOwner $registered $InstallDir)) {
    Disable-ScheduledTask -TaskName 'DVielle' -TaskPath '\' | Out-Null
    throw 'Registered task settings did not match the resident-agent safety requirements; task disabled.'
}
$oldGui = Get-ScheduledTask -TaskName 'DVielleGUI' -TaskPath '\' -ErrorAction SilentlyContinue
if ($oldGui -and (Test-DvielleTaskOwner $oldGui $InstallDir)) {
    Unregister-ScheduledTask -TaskName 'DVielleGUI' -TaskPath '\' -Confirm:$false
}

$shell = New-Object -ComObject WScript.Shell
$startMenu = [Environment]::GetFolderPath('Programs')
foreach ($directory in @($startMenu, [Environment]::GetFolderPath('Desktop'))) {
    $shortcut = $shell.CreateShortcut((Join-Path $directory 'DVielle - Deep Vigilance.lnk'))
    $shortcut.TargetPath = $pythonw
    $shortcut.Arguments = '-m dvielle'
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.Description = 'DVielle - Deep Vigilance'
    $icon = Join-Path $InstallDir 'assets\brand\dvielle.ico'
    if (Test-Path -LiteralPath $icon) { $shortcut.IconLocation = "$icon,0" }
    $shortcut.Save()
}
$uninstall = $shell.CreateShortcut((Join-Path $startMenu 'Uninstall DVielle.lnk'))
$uninstall.TargetPath = Join-Path $InstallDir 'installer\Uninstall-DVielle.bat'
$uninstall.WorkingDirectory = Join-Path $InstallDir 'installer'
$uninstall.Save()
$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DVielle'
if (-not (Test-Path -LiteralPath $regPath)) { New-Item -Path $regPath | Out-Null }
$version = [regex]::Match($metadata, '(?m)^version\s*=\s*"([^"]+)"').Groups[1].Value
Set-ItemProperty -Path $regPath -Name DisplayName -Value 'DVielle - Deep Vigilance'
Set-ItemProperty -Path $regPath -Name DisplayVersion -Value $version
Set-ItemProperty -Path $regPath -Name Publisher -Value 'DVielle'
Set-ItemProperty -Path $regPath -Name InstallLocation -Value $InstallDir
Set-ItemProperty -Path $regPath -Name UninstallString -Value ('"' + (Join-Path $InstallDir 'installer\Uninstall-DVielle.bat') + '"')

# Scheduler owns the only launch; no extra unmanaged Start-Process instance.
Push-Location $InstallDir
try {
    Enable-ScheduledTask -TaskName 'DVielle' -TaskPath '\' | Out-Null
    Start-ScheduledTask -TaskName 'DVielle' -TaskPath '\'
    Invoke-DvielleNative $python @('scripts\verify_runtime.py', '--config-dir', (Join-Path $InstallDir 'config'), '--timeout', '30')
} catch {
    Disable-ScheduledTask -TaskName 'DVielle' -TaskPath '\' | Out-Null
    Write-Warning 'The resident heartbeat could not be verified. Startup is disabled; inspect data\logs before retrying.'
    throw
} finally { Pop-Location }
Write-Host 'Installation checks passed and a current resident heartbeat was verified. Open the desktop shortcut for the console.' -ForegroundColor Green
