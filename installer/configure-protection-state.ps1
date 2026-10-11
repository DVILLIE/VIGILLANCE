#Requires -Version 5.1
<# Explicit administrator setup of private helper state from a trusted installation. #>
param(
    [Parameter(Mandatory)][string]$UserSid,
    [string]$InstallDir = (Split-Path -Parent $PSScriptRoot)
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
if (-not (Test-DvielleAdmin)) { throw 'Protection configuration requires Windows Administrator approval.' }
if ($UserSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'Specify the exact Windows user SID, not a service or group identity.' }
$InstallDir = Resolve-DvielleRoot $InstallDir
if ($InstallDir -ine (Resolve-DvielleRoot (Split-Path -Parent $PSScriptRoot))) { throw 'Use the exact trusted installed configuration program.' }
Assert-DvielleTrustedExecutionTree $InstallDir -RuntimePrivateSid $UserSid
$python = Join-Path $InstallDir '.venv\Scripts\python.exe'
Assert-DvielleTrustedExecutionTree $python
# Resolve the account type through Windows. A similarly formatted domain group
# SID must not become a privileged pipe's authorized user.
Invoke-DvielleNative $python @('-I', '-B', '-c', 'import sys, win32security as w; a=w.LookupAccountSid(None,w.ConvertStringSidToSid(sys.argv[1])); sys.exit(0 if a[2]==w.SidTypeUser else 1)', $UserSid)
$common = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
if (-not $common) { throw 'Windows common application data could not be resolved.' }
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $acl.AddAccessRule((New-DvielleElevationRule -Sid $sid -Rights FullControl -Directory))
}
foreach ($directory in @((Join-Path $common 'DVielle'), (Join-Path $common 'DVielle\privileged'))) {
    $directory = Resolve-DvielleRoot $directory
    if (-not (Test-DvielleProtectedAncestors $directory)) { throw 'State ancestors allow untrusted replacement.' }
    if (-not (Test-Path -LiteralPath $directory)) {
        $null = [IO.Directory]::CreateDirectory($directory, $acl)
    }
    # Never repair/bless a pre-existing mutable directory by changing its ACL.
    Assert-DvielleTrustedExecutionTree $directory
}
$configuration = Join-Path $common 'DVielle\privileged\installation.json'
if (Test-Path -LiteralPath $configuration) { throw 'Installation binding already exists. Migration must preserve its grants and recovery records.' }
$bytes = [Text.Encoding]::UTF8.GetBytes((@{ version = 1; user_sid = $UserSid } | ConvertTo-Json -Compress))
$stream = New-Object IO.FileStream($configuration, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
Assert-DvielleTrustedExecutionTree (Split-Path -Parent $configuration)
Write-Output 'Protected user binding created. No service was registered or started; no firewall rule changed.'
