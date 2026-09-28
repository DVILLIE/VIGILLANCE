#Requires -Version 5.1
param([Parameter(Mandatory)][ValidateSet('Install', 'Uninstall')][string]$Operation)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$script = Join-Path $PSScriptRoot ($Operation.ToLowerInvariant() + '-dvielle.ps1')
if (Test-DvielleAdmin) {
    # Invoking a script does not reliably update LASTEXITCODE. Exceptions determine failure here.
    try { & $script; exit 0 } catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
# An explicitly launched installer is interactive; preserve its actual elevated exit code.
# RunAs elevates this installer process only. The resident task stays Limited unless
# install-dvielle.ps1 is invoked with -RunLevel Highest, and that path refuses to
# create the task unless the install directory ACL lockdown succeeds.
$arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $script + '"'
try {
    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Verb RunAs -Wait -PassThru
    exit $process.ExitCode
} catch { Write-Error $_ -ErrorAction Continue; exit 1 }
