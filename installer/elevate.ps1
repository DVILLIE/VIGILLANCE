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
# RunAs elevates this installer process only. The resident task stays Limited.
# install-dvielle.ps1 refuses Highest before any installation changes. Source and
# interpreter preflight requires protected staging; data/config remain private.
$arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $script + '"'
try {
    $systemPowerShell = Get-DvielleSystemExecutable 'WindowsPowerShell\v1.0\powershell.exe'
    $process = Start-Process -FilePath $systemPowerShell -ArgumentList $arguments -Verb RunAs -Wait -PassThru
    exit $process.ExitCode
} catch { Write-Error $_ -ErrorAction Continue; exit 1 }
