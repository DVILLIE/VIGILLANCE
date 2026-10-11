#Requires -Version 5.1
<#
  Entry point for the setup executable.
  Installs pinned official Python 3.14.8 when the protected runtime is missing,
  then calls install-dvielle.ps1 with -RunLevel Limited.
  This script has no RunLevel parameter. It does not elevate the resident task.
#>
[CmdletBinding()]
param(
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$InstallDir = (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'DVielle'),
    [string]$PythonInstaller = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

function Get-DviellePython314Pin {
    $pinPath = Join-Path $PSScriptRoot 'python-3.14.8.pin.json'
    if (-not (Test-Path -LiteralPath $pinPath)) { throw "Missing Python pin: $pinPath" }
    return (Get-Content -LiteralPath $pinPath -Raw | ConvertFrom-Json)
}

function Test-DviellePython314 {
    return (Get-DvielleTrustedPython314)
}

function Install-DviellePinnedPython314 {
    param([Parameter(Mandatory)][string]$InstallerPath)
    $pin = Get-DviellePython314Pin
    $resolved = (Resolve-Path -LiteralPath $InstallerPath).Path
    Assert-DvielleTrustedExecutionTree $resolved
    $lease = [IO.File]::Open($resolved,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
    $hash = ([BitConverter]::ToString($algorithm.ComputeHash($lease))).Replace('-','')
    $expected = ([string]$pin.sha256).Trim().ToUpperInvariant()
    if ($hash -ne $expected) {
        throw 'Python installer hash does not match the pin. Refusing to run it.'
    }
    $length = $lease.Length
    if ([int64]$length -ne [int64]$pin.size) {
        throw 'Python installer size does not match the pin. Refusing to run it.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $resolved
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'CN=Python Software Foundation(?:,|$)') {
        throw 'Valid Python Software Foundation signature required.'
    }
    $runtimeTarget = [string]$pin.target_directory
    if ((Test-Path -LiteralPath $runtimeTarget) -or -not (Test-DvielleProtectedAncestors $runtimeTarget)) {
        throw 'Runtime destination exists or has unsafe ancestors; review it before replacement.'
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
    } finally { $algorithm.Dispose(); $lease.Dispose() }
}

if (-not (Test-DvielleAdmin)) { throw 'Run the D''Vielle setup as Administrator.' }
$SourceRoot = Resolve-DvielleRoot $SourceRoot
Assert-DvielleTrustedExecutionTree $SourceRoot
Write-Host 'D''Vielle setup. The resident logon task stays Limited.'

$python = Test-DviellePython314
if (-not $python) {
    if (-not $PythonInstaller) {
        throw 'Protected Python 3.14.8 is unavailable. Use the verified official runtime installer from the protected stage.'
    }
    Install-DviellePinnedPython314 -InstallerPath $PythonInstaller
    $python = Test-DviellePython314
    if (-not $python) {
        throw 'The installer finished, but protected Python 3.14.8 was not found. Inspect the Windows Temp installer log.'
    }
}

& $python -I -c 'import tkinter'
if ($LASTEXITCODE -ne 0) {
    throw 'Python 3.14 is present, but tkinter did not import. The official installer must include Tcl/Tk (Include_tcltk=1).'
}

& (Join-Path $PSScriptRoot 'install-dvielle.ps1') -SourceRoot $SourceRoot -InstallDir $InstallDir -PythonExecutable $python -RunLevel Limited
