#Requires -Version 5.1
<#
  Entry point for the setup executable.
  Installs the pinned official Python 3.12.10 build only when 3.12 is missing,
  then calls install-dvielle.ps1 with -RunLevel Limited.
  This script has no RunLevel parameter. It does not elevate the resident task.
#>
[CmdletBinding()]
param(
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$InstallDir = 'C:\DVILLIE',
    [string]$PythonInstaller = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

function Get-DviellePython312Pin {
    $pinPath = Join-Path $PSScriptRoot 'python-3.12.10.pin.json'
    if (-not (Test-Path -LiteralPath $pinPath)) { throw "Missing Python pin: $pinPath" }
    return (Get-Content -LiteralPath $pinPath -Raw | ConvertFrom-Json)
}

function Test-DviellePython312 {
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
    return $null
}

function Install-DviellePinnedPython312 {
    param([Parameter(Mandatory)][string]$InstallerPath)
    $pin = Get-DviellePython312Pin
    $resolved = (Resolve-Path -LiteralPath $InstallerPath).Path
    $hash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
    $expected = ([string]$pin.sha256).Trim().ToUpperInvariant()
    if ($hash -ne $expected) {
        throw 'Python installer hash does not match the pin. Refusing to run it.'
    }
    $length = (Get-Item -LiteralPath $resolved).Length
    if ([int64]$length -ne [int64]$pin.size) {
        throw 'Python installer size does not match the pin. Refusing to run it.'
    }
    $log = Join-Path $env:SystemRoot ('Temp\DVielle-' + [string]$pin.filename + '.log')
    $arguments = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @($pin.silent_args)) { $arguments.Add([string]$item) }
    $arguments.Add('/log')
    $arguments.Add($log)
    Write-Host "Installing official Python $([string]$pin.version) (64-bit). This can take a few minutes."
    $proc = Start-Process -FilePath $resolved -ArgumentList $arguments.ToArray() -Wait -PassThru -NoNewWindow
    if (-not $proc -or $null -eq $proc.ExitCode) {
        throw "Python installer did not return an exit code. Log: $log"
    }
    # 3010 means success plus a reboot request. The interpreter is usually usable before that reboot.
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        throw "Python $([string]$pin.version) installer failed with exit code $($proc.ExitCode). Log: $log"
    }
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($machinePath -or $userPath) {
        $env:Path = (@($machinePath, $userPath) | Where-Object { $_ }) -join ';'
    }
    if ($proc.ExitCode -eq 3010) {
        Write-Host 'Python reported that a reboot may be required (exit 3010). Continuing this install.'
    }
}

if (-not (Test-DvielleAdmin)) { throw 'Run the DVielle setup as Administrator.' }
Write-Host 'DVielle setup. The resident logon task stays Limited.'

$python = Test-DviellePython312
if (-not $python) {
    if (-not $PythonInstaller) {
        throw 'Python 3.12 is not installed. Use the DVielle setup executable, which bundles the official installer, or install Python 3.12 from python.org and run Install-DVielle.bat.'
    }
    Install-DviellePinnedPython312 -InstallerPath $PythonInstaller
    $python = Test-DviellePython312
    if (-not $python) {
        throw 'The Python installer finished, but Python 3.12 was not found on PATH. See C:\Windows\Temp\DVielle-python-3.12.10-amd64.exe.log'
    }
}

& $python -c 'import tkinter'
if ($LASTEXITCODE -ne 0) {
    throw 'Python 3.12 is present, but tkinter did not import. CustomTkinter needs Tcl/Tk from the official installer (Include_tcltk=1).'
}

& (Join-Path $PSScriptRoot 'install-dvielle.ps1') -SourceRoot $SourceRoot -InstallDir $InstallDir -RunLevel Limited
