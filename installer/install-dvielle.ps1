#Requires -Version 5.1
<# Install with protected Python 3.14.8 or newer in the 3.14 series. #>
param(
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$InstallDir = (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'DVielle'),
    [string]$DependencyBundle = '',
    [string]$PythonExecutable = '',
    # Limited is TASK_RUNLEVEL_LUA (least privileges). Highest is TASK_RUNLEVEL_HIGHEST.
    # https://learn.microsoft.com/en-us/windows/win32/taskschd/principal-runlevel
    # https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal
    # Highest remains a recognized argument so legacy callers get an explicit
    # safety refusal. It is held until protected code/private data are separated.
    [ValidateSet('Limited', 'Highest')]
    [string]$RunLevel = 'Limited'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

function Resolve-Python314 {
    # Do not execute the launcher and discover its selected interpreter after
    # the fact: py may select a writable per-user runtime. Resolve first.
    $resolved = Get-DvielleTrustedPython314
    if ($resolved) { return $resolved }
    throw 'Protected Python 3.14.8 or newer in the 3.14 series is required. Per-user writable interpreters are refused.'
}

if (-not (Test-DvielleAdmin)) { throw 'Run installer\Install-DVielle.bat as Administrator.' }
if ($RunLevel -eq 'Highest') {
    throw 'Refusing to create or enable a Highest scheduled task: protected code and private writable data have not yet been separated. Use Limited.'
}
$srcRoot = Resolve-DvielleRoot $SourceRoot
$InstallDir = Resolve-DvielleRoot $InstallDir
$installedUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
foreach ($required in @('agent\main.py', 'dvielle\__main__.py', 'pyproject.toml', 'config\config.yaml', 'scripts\smoke_test.py', 'scripts\verify_runtime.py')) {
    if (-not (Test-Path -LiteralPath (Join-Path $srcRoot $required) -PathType Leaf)) {
        throw "Invalid source tree: missing $required. Nothing installed."
    }
}
$metadata = Get-Content -LiteralPath (Join-Path $srcRoot 'pyproject.toml') -Raw
if ($metadata -notmatch '(?m)^name\s*=\s*"dvielle"\s*$') { throw 'Source metadata is not the D''Vielle project.' }
if ($InstallDir.StartsWith($srcRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
    $srcRoot.StartsWith($InstallDir + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Source and destination may be identical, but neither may be nested inside the other.'
}
# Source permissions are a necessary precondition, not source authenticity.
# Do not "bless" an already writable tree by changing its ACL and running it.
if ($srcRoot -ieq $InstallDir) {
    Assert-DvielleTrustedExecutionTree $srcRoot -RuntimePrivateSid $installedUserSid
} else {
    Assert-DvielleTrustedExecutionTree $srcRoot
}
if (Test-Path -LiteralPath $InstallDir) {
    Assert-DvielleTrustedExecutionTree $InstallDir -RuntimePrivateSid $installedUserSid
} elseif (-not (Test-DvielleProtectedAncestors $InstallDir)) {
    throw 'Refusing installation under an ancestor that can replace the protected code root.'
}
if ($PythonExecutable) {
    $PythonExecutable = [IO.Path]::GetFullPath($PythonExecutable)
    Assert-DvielleTrustedExecutionTree $PythonExecutable
    Invoke-DvielleNative $PythonExecutable @('-I', '-B', '-c', 'import sys; sys.exit(0 if sys.version_info[:2] == (3,14) and sys.version_info[:3] >= (3,14,8) else 1)')
    $basePython = $PythonExecutable
} else { $basePython = Resolve-Python314 }
if (-not $DependencyBundle) { $DependencyBundle = Join-Path $srcRoot 'offline-dependencies' }
$DependencyBundle = Resolve-DvielleRoot $DependencyBundle
Assert-DvielleTrustedExecutionTree $DependencyBundle
Assert-DvielleOfflineDependencies $DependencyBundle
Write-Host "Installing D'Vielle to $InstallDir with the verified runtime at $basePython."

# Disable owned startup triggers before quiescing the runtime, so it cannot restart during copying.
foreach ($relative in @('agent', 'dvielle', 'scripts', 'installer', 'tests', 'docs', 'assets', 'config', 'requirements.txt', 'pyproject.toml', 'README.md')) {
    Assert-DvielleTreeNoReparse $srcRoot (Join-Path $srcRoot $relative)
    Assert-DvielleTreeNoReparse $InstallDir (Join-Path $InstallDir $relative)
}
foreach ($relative in @('data', '.venv')) { Assert-DvielleTreeNoReparse $InstallDir (Join-Path $InstallDir $relative) }
Disable-DvielleOwnedTasks $InstallDir
if (Test-Path -LiteralPath (Join-Path $InstallDir 'agent\main.py')) { Stop-DvielleOwnedRuntime $InstallDir }

if (-not (Test-Path -LiteralPath $InstallDir)) {
    # Apply protection at creation, rather than creating a writable directory
    # and trusting its contents after a later ACL change (PowerShell 5.1/.NET).
    $null = [IO.Directory]::CreateDirectory($InstallDir, (Get-DvielleElevationAcl -Directory))
    # CreateDirectory can also return an already-existing directory. If another
    # user pre-created the name, reject its owner/ACL/content before copying or
    # creating anything inside it. Parent replacement rights were refused above.
    Assert-DvielleTrustedExecutionTree $InstallDir
}
if ($srcRoot -ine $InstallDir) {
    foreach ($folder in @('agent', 'dvielle', 'scripts', 'installer', 'tests', 'docs', 'assets')) {
        $source = Join-Path $srcRoot $folder
        if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination $InstallDir -Recurse -Force }
    }
    foreach ($file in @('requirements.txt', 'pyproject.toml', 'README.md', 'LICENSE')) {
        Copy-Item -LiteralPath (Join-Path $srcRoot $file) -Destination $InstallDir -Force
    }
    # Do not write through an existing user-mutable config subtree as Admin.
    # New defaults are copied only while the new subtree is still protected.
    if (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'config'))) {
        foreach ($file in Get-ChildItem -LiteralPath (Join-Path $srcRoot 'config') -File -Recurse) {
            $relative = $file.FullName.Substring($srcRoot.Length + 1)
            $target = Join-Path $InstallDir $relative
            New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
            Copy-Item -LiteralPath $file.FullName -Destination $target
        }
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'data'))) {
    New-Item -ItemType Directory -Path (Join-Path $InstallDir 'data\logs') -Force | Out-Null
}
foreach ($relative in @('data', 'config')) {
    Set-DviellePrivateRuntimeTree -Root $InstallDir -Relative $relative -UserSid $installedUserSid
}
$venv = Join-Path $InstallDir '.venv'
$python = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { Invoke-DvielleNative $basePython @('-I', '-m', 'venv', $venv) }
Assert-DvielleTrustedExecutionTree $InstallDir -RuntimePrivateSid $installedUserSid
Invoke-DvielleNative $python @('-I', '-B', '-c', 'import sys; sys.exit(0 if sys.version_info[:2] == (3,14) and sys.version_info[:3] >= (3,14,8) else 1)')
$pythonw = Join-Path $venv 'Scripts\pythonw.exe'
if (-not (Test-Path -LiteralPath $pythonw)) { throw 'The Python 3.14 environment lacks pythonw.exe.' }
Push-Location $InstallDir
try {
    # Closed, hashed offline dependency set. Never resolve network packages or
    # source distributions inside this Administrator installation.
    Invoke-DvielleNative $python @('-I', '-m', 'pip', '--isolated', '--disable-pip-version-check', 'install', '--no-index', '--no-cache-dir', '--only-binary=:all:', '--require-hashes', '--find-links', (Join-Path $DependencyBundle 'wheels'), '--requirement', (Join-Path $DependencyBundle 'requirements.lock'))
    # The already-protected local source is the only build input. Build tools
    # were installed above; isolation/dependency fetching are both disabled.
    Invoke-DvielleNative $python @('-I', '-m', 'pip', '--isolated', '--disable-pip-version-check', 'install', '--no-index', '--no-deps', '--no-build-isolation', '-e', '.[windows]')
    Assert-DvielleTrustedExecutionTree $InstallDir -RuntimePrivateSid $installedUserSid
    Invoke-DvielleNative $python @('-I', '-m', 'pip', '--isolated', 'check')
    # No collector execution, persistence, cloud lookup, or machine mutation in this check.
    Invoke-DvielleNative $python @('-I', 'scripts\smoke_test.py')
} finally { Pop-Location }

# Branded console host: same-folder copy of pythonw with dvielle.ico (Task Manager process identity).
# Resident logon task stays pythonw -m agent.main.
$guiShimScript = Join-Path $InstallDir 'scripts\New-DvielleGuiExe.ps1'
if (-not (Test-Path -LiteralPath $guiShimScript -PathType Leaf)) {
    throw 'Missing scripts\New-DvielleGuiExe.ps1; cannot brand the console host.'
}
& $guiShimScript -InstallDir $InstallDir
$guiExe = Join-Path $venv 'Scripts\DVielle.exe'
if (-not (Test-Path -LiteralPath $guiExe -PathType Leaf)) { throw 'Branded DVielle.exe GUI shim was not created.' }

# GUIDs avoid localized Logon and Credential Validation display names (4625 and 4776).
$auditpol = Get-DvielleSystemExecutable 'auditpol.exe'
foreach ($subcategory in @('{0CCE9215-69AE-11D9-BED3-505054503030}', '{0CCE923F-69AE-11D9-BED3-505054503030}')) {
    Invoke-DvielleNative $auditpol @('/set', ('/subcategory:' + $subcategory), '/failure:enable')
    Invoke-DvielleNative $auditpol @('/get', ('/subcategory:' + $subcategory))
}

# All prerequisites have passed before task activation.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$settings = New-ScheduledTaskSettingsSet -Disable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
$settings.ExecutionTimeLimit = 'PT0S'
# Resident task RunLevel defaults to Limited (least privileges / LUA).
# elevate.ps1 RunAs only elevates this installer process. Highest was refused
# during preflight; permission lockdown alone cannot make this layout safe.
# https://learn.microsoft.com/en-us/windows/win32/taskschd/principal-runlevel
# https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks
$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel $RunLevel
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
$action = New-ScheduledTaskAction -Execute $pythonw -Argument '-m agent.main' -WorkingDirectory $InstallDir
# Keep the scheduler identity stable across branding changes and uninstall.
Register-ScheduledTask -TaskName 'DVielle' -TaskPath '\' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description 'D''Vielle resident monitor' -Force | Out-Null
$registered = Get-ScheduledTask -TaskName 'DVielle' -TaskPath '\'
if ($registered.Settings.ExecutionTimeLimit -ne 'PT0S' -or $registered.Settings.MultipleInstances -ne 'IgnoreNew' -or
    $registered.Settings.RestartCount -ne 3 -or
    [string]$registered.Principal.RunLevel -ne $RunLevel -or
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
    $shortcut = $shell.CreateShortcut((Join-Path $directory "D'Vielle - Intelligent Vigilance.lnk"))
    $shortcut.TargetPath = $guiExe
    $shortcut.Arguments = '-m dvielle'
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.Description = "D'Vielle - Intelligent Vigilance"
    $icon = Join-Path $InstallDir 'assets\brand\dvielle.ico'
    if (Test-Path -LiteralPath $icon) { $shortcut.IconLocation = "$icon,0" }
    else { $shortcut.IconLocation = "$guiExe,0" }
    $shortcut.Save()
}
$uninstall = $shell.CreateShortcut((Join-Path $startMenu "Uninstall D'Vielle.lnk"))
$uninstall.TargetPath = Join-Path $InstallDir 'installer\Uninstall-DVielle.bat'
$uninstall.WorkingDirectory = Join-Path $InstallDir 'installer'
$uninstall.Save()
$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DVielle'
if (-not (Test-Path -LiteralPath $regPath)) { New-Item -Path $regPath | Out-Null }
$version = [regex]::Match($metadata, '(?m)^version\s*=\s*"([^"]+)"').Groups[1].Value
Set-ItemProperty -Path $regPath -Name DisplayName -Value "D'Vielle - Intelligent Vigilance"
Set-ItemProperty -Path $regPath -Name DisplayVersion -Value $version
$iconPath = Join-Path $InstallDir 'assets\brand\dvielle.ico'
if (Test-Path -LiteralPath $guiExe) { Set-ItemProperty -Path $regPath -Name DisplayIcon -Value ($guiExe + ',0') }
elseif (Test-Path -LiteralPath $iconPath) { Set-ItemProperty -Path $regPath -Name DisplayIcon -Value ($iconPath + ',0') }
Set-ItemProperty -Path $regPath -Name Publisher -Value "D'Vielle"
Set-ItemProperty -Path $regPath -Name InstallLocation -Value $InstallDir
Set-ItemProperty -Path $regPath -Name UninstallString -Value ('"' + (Join-Path $InstallDir 'installer\Uninstall-DVielle.bat') + '"')

# Scheduler owns the only launch; no extra unmanaged Start-Process instance.
Push-Location $InstallDir
try {
    Enable-ScheduledTask -TaskName 'DVielle' -TaskPath '\' | Out-Null
    Start-ScheduledTask -TaskName 'DVielle' -TaskPath '\'
    Invoke-DvielleNative $python @('-I', 'scripts\verify_runtime.py', '--config-dir', (Join-Path $InstallDir 'config'), '--timeout', '30')
} catch {
    # Disable only if the task still exists; retain the original failure.
    $existing = Get-ScheduledTask -TaskName 'DVielle' -TaskPath '\' -ErrorAction SilentlyContinue
    if ($existing) {
        Disable-ScheduledTask -TaskName 'DVielle' -TaskPath '\' -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Warning 'The resident heartbeat could not be verified. Startup is disabled; inspect data\logs before retrying.'
    throw
} finally { Pop-Location }
Write-Host 'Installation checks passed and a current resident heartbeat was verified. Open the desktop shortcut for the console.' -ForegroundColor Green
