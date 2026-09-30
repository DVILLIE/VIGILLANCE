#Requires -Version 5.1
<#
  Build dist\DVielle-Setup-<version>.exe on Windows.
  Downloads the pinned official Python 3.12.10 installer and, if needed, the
  pinned Inno Setup 6.4.0 compiler. Does not publish a GitHub Release.
#>
[CmdletBinding()]
param(
    [string]$Iscc = ''
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $Root 'installer\common.ps1')

function Get-DviellePin {
    param([Parameter(Mandatory)][string]$Name)
    $path = Join-Path $Root (Join-Path 'installer' $Name)
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing pin: $path" }
    return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
}

function Test-DviellePinnedFile {
    param($Pin, [Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    $expected = ([string]$Pin.sha256).Trim().ToUpperInvariant()
    $size = (Get-Item -LiteralPath $Path).Length
    return ($hash -eq $expected -and [int64]$size -eq [int64]$Pin.size)
}

function Get-DviellePinnedDownload {
    param($Pin, [Parameter(Mandatory)][string]$Destination)
    if (Test-DviellePinnedFile $Pin $Destination) { return }
    $parent = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Force }
    Write-Host "Downloading $([string]$Pin.url)"
    & curl.exe -fsSL --output $Destination $([string]$Pin.url)
    if ($LASTEXITCODE -ne 0) { throw "Download failed: $([string]$Pin.url)" }
    if (-not (Test-DviellePinnedFile $Pin $Destination)) {
        throw "Downloaded file does not match the pin: $([string]$Pin.filename)"
    }
}

function ConvertTo-DvielleInnoPath {
    param([Parameter(Mandatory)][string]$Path)
    # ISPP treats backslash as an escape. Inno accepts forward slashes.
    $full = ([IO.Path]::GetFullPath($Path)) -replace '\\', '/'
    if ($full -match '[\s"]') { throw "Build path cannot contain spaces or quotes: $full" }
    return $full
}

$pythonPin = Get-DviellePin 'python-3.12.10.pin.json'
$innoPin = Get-DviellePin 'inno-setup-6.4.0.pin.json'
if (-not $Iscc) { $Iscc = [string]$innoPin.iscc }

$outputDir = Join-Path $Root 'dist'
$cache = Join-Path $outputDir 'cache'
New-Item -ItemType Directory -Path $cache -Force | Out-Null
$pythonExe = Join-Path $cache ([string]$pythonPin.filename)
Get-DviellePinnedDownload -Pin $pythonPin -Destination $pythonExe

if (-not (Test-Path -LiteralPath $Iscc)) {
    if (-not (Test-DvielleAdmin)) {
        throw "Inno Setup compiler not found at $Iscc. Install Inno Setup $([string]$innoPin.version), or run this script as Administrator so it can install the pinned compiler."
    }
    $innoExe = Join-Path $cache ([string]$innoPin.filename)
    Get-DviellePinnedDownload -Pin $innoPin -Destination $innoExe
    $innoArgs = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @($innoPin.silent_args)) { $innoArgs.Add([string]$item) }
    $proc = Start-Process -FilePath $innoExe -ArgumentList $innoArgs.ToArray() -Wait -PassThru
    if (-not $proc -or $proc.ExitCode -ne 0) {
        throw "Inno Setup installer failed with exit code $($proc.ExitCode)."
    }
    if (-not (Test-Path -LiteralPath $Iscc)) { throw "ISCC.exe was not found after installing Inno Setup: $Iscc" }
}

$stage = Join-Path $outputDir 'payload'
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
foreach ($folder in @('agent', 'dvielle', 'scripts', 'installer', 'tests', 'docs', 'assets', 'config')) {
    $source = Join-Path $Root $folder
    if (-not (Test-Path -LiteralPath $source)) { throw "Missing source folder: $folder" }
    Copy-Item -LiteralPath $source -Destination (Join-Path $stage $folder) -Recurse -Force
}
foreach ($file in @('requirements.txt', 'pyproject.toml', 'README.md', 'LICENSE')) {
    $source = Join-Path $Root $file
    if (-not (Test-Path -LiteralPath $source)) { throw "Missing source file: $file" }
    Copy-Item -LiteralPath $source -Destination (Join-Path $stage $file) -Force
}
Get-ChildItem -LiteralPath $stage -Recurse -Directory -Filter '__pycache__' -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force }

$metadata = Get-Content -LiteralPath (Join-Path $Root 'pyproject.toml') -Raw
$version = [regex]::Match($metadata, '(?m)^version\s*=\s*"([^"]+)"').Groups[1].Value
if (-not $version) { throw 'version is missing from pyproject.toml' }
$info = $version
if (@($version.Split('.')).Count -eq 3) { $info = "$version.0" }

$iss = Join-Path $Root 'installer\DVielle.iss'
& $Iscc @(
    "/DAppVersion=$version",
    ("/DVersionInfoVersion=$info"),
    ("/DPayloadDir=" + (ConvertTo-DvielleInnoPath $stage)),
    ("/DPythonInstaller=" + (ConvertTo-DvielleInnoPath $pythonExe)),
    ("/DOutputDir=" + (ConvertTo-DvielleInnoPath $outputDir)),
    $iss
)
if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit code $LASTEXITCODE" }
$built = Join-Path $outputDir "DVielle-Setup-$version.exe"
if (-not (Test-Path -LiteralPath $built)) { throw "Expected setup executable was not written: $built" }
Write-Host "Built $built"
Write-Host 'This file is unsigned. It is not uploaded to a GitHub Release by this script.'
