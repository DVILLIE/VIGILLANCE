#Requires -Version 5.1
<#
  Build .venv\Scripts\DVielle.exe: a same-folder copy of pythonw.exe with the
  DVielle ICO and FileDescription stamped by rcedit. Task Manager then shows
  DVielle.exe (branded) for the console. The resident logon task stays pythonw
  -m agent.main and is not modified here.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InstallDir,
    [string]$IconPath = '',
    [string]$RceditPath = '',
    [string]$Version = ''
)
$ErrorActionPreference = 'Stop'
$InstallDir = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
$venvPythonw = Join-Path $InstallDir '.venv\Scripts\pythonw.exe'
if (-not (Test-Path -LiteralPath $venvPythonw -PathType Leaf)) {
    throw "Missing venv pythonw.exe at $venvPythonw. Install the Python environment first."
}
if (-not $IconPath) { $IconPath = Join-Path $InstallDir 'assets\brand\dvielle.ico' }
if (-not (Test-Path -LiteralPath $IconPath -PathType Leaf)) {
    throw "Missing brand icon: $IconPath"
}
if (-not $RceditPath) {
    $RceditPath = Join-Path $InstallDir 'installer\tools\rcedit-x64.exe'
}
if (-not (Test-Path -LiteralPath $RceditPath -PathType Leaf)) {
    throw "Missing rcedit: $RceditPath"
}

$pinPath = Join-Path $InstallDir 'installer\rcedit-x64.pin.json'
if (Test-Path -LiteralPath $pinPath -PathType Leaf) {
    $pin = Get-Content -LiteralPath $pinPath -Raw | ConvertFrom-Json
    $hash = (Get-FileHash -LiteralPath $RceditPath -Algorithm SHA256).Hash
    $expected = ([string]$pin.sha256).Trim().ToUpperInvariant()
    $size = (Get-Item -LiteralPath $RceditPath).Length
    if ($hash -ne $expected -or [int64]$size -ne [int64]$pin.size) {
        throw "rcedit-x64.exe does not match installer/rcedit-x64.pin.json (hash or size)."
    }
}

if (-not $Version) {
    $meta = Get-Content -LiteralPath (Join-Path $InstallDir 'pyproject.toml') -Raw
    $match = [regex]::Match($meta, '(?m)^version\s*=\s*"([^"]+)"')
    if (-not $match.Success) { throw 'Could not read version from pyproject.toml.' }
    $Version = $match.Groups[1].Value
}
$fileVersion = $Version
if ($fileVersion -notmatch '^\d+\.\d+\.\d+\.\d+$') {
    $parts = $fileVersion.Split('.')
    while ($parts.Count -lt 4) { $parts += '0' }
    $fileVersion = ($parts[0..3] -join '.')
}

$guiExe = Join-Path $InstallDir '.venv\Scripts\DVielle.exe'
# Close only fails soft: install may run while no GUI is open.
$existing = Get-Process -Name 'DVielle' -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and ($_.Path -ieq $guiExe) }
foreach ($proc in @($existing)) {
    $null = $proc.CloseMainWindow()
}
$deadline = [DateTime]::UtcNow.AddSeconds(5)
while (@(Get-Process -Name 'DVielle' -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and ($_.Path -ieq $guiExe) }).Count -gt 0 -and
        [DateTime]::UtcNow -lt $deadline) {
    Start-Sleep -Milliseconds 200
}
if (Test-Path -LiteralPath $guiExe) {
    Remove-Item -LiteralPath $guiExe -Force -ErrorAction Stop
}
Copy-Item -LiteralPath $venvPythonw -Destination $guiExe -Force

# Call operator keeps --flags intact (Start-Process ArgumentList can split them).
& $RceditPath `
    $guiExe `
    --set-icon $IconPath `
    --set-version-string FileDescription 'DVielle - Deep Vigilance' `
    --set-version-string ProductName DVielle `
    --set-version-string CompanyName DVielle `
    --set-version-string OriginalFilename DVielle.exe `
    --set-product-version $Version `
    --set-file-version $fileVersion
if ($LASTEXITCODE -ne 0) {
    throw "rcedit failed with exit code $LASTEXITCODE while branding DVielle.exe."
}
if (-not (Test-Path -LiteralPath $guiExe -PathType Leaf)) {
    throw 'DVielle.exe was not created.'
}
Write-Host "Branded GUI shim ready: $guiExe (version $Version)"
