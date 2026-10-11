#Requires -Version 5.1
<# Launch the official signed runtime with normal Windows Administrator approval. #>
param([string]$InstallerPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'dist\python-3.14.8-amd64.exe'))
$ErrorActionPreference = 'Stop'
$InstallerPath = [IO.Path]::GetFullPath($InstallerPath)
$target = 'C:\Program Files\DVielleRuntime\Python314'
if (Test-Path -LiteralPath $target) { throw 'Runtime target already exists; review it before replacing anything.' }
$lease = [IO.File]::Open($InstallerPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
$sha = [Security.Cryptography.SHA256]::Create()
try {
    if ($lease.Length -ne 33387464) { throw 'Official runtime installer size mismatch.' }
    $digest = ([BitConverter]::ToString($sha.ComputeHash($lease))).Replace('-','').ToLowerInvariant()
    if ($digest -cne '759be887b96e736a3ca886daf8d575f18fcae1a09efab6902f42d59e8999f8ef') { throw 'Official Python.org release hash mismatch.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $InstallerPath
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'CN=Python Software Foundation(?:,|$)') { throw 'Valid Python Software Foundation signature required.' }
    $arguments = '/quiet InstallAllUsers=1 TargetDir="C:\Program Files\DVielleRuntime\Python314" PrependPath=0 Include_launcher=0 Include_pip=1 Include_tcltk=1 Include_test=0 Include_doc=0 Shortcuts=0 AssociateFiles=0 /log "C:\Windows\Temp\DViellePython314.log"'
    $process = Start-Process -FilePath $InstallerPath -WorkingDirectory ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -Wait -PassThru
    if ($process.ExitCode -notin @(0,3010)) { throw ('Official runtime installation failed; exit ' + $process.ExitCode) }
    if (-not (Test-Path -LiteralPath (Join-Path $target 'python.exe') -PathType Leaf)) { throw 'Installer exited but target interpreter is absent.' }
    Write-Output ('Runtime installer completed; exit ' + $process.ExitCode + '. Separate protected-path and compatibility verification is still required.')
} finally { $sha.Dispose(); $lease.Dispose() }
# Finish the Explorer launcher as well as the installer; do not leave an idle
# console waiting after a successful quiet installation.
exit 0
