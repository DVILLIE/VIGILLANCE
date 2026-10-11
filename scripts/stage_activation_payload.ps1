#Requires -Version 5.1
<# Local operator-approved payload staging. No service registration or activation. #>
param(
    [Parameter(Mandatory)][string]$Archive,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ApprovedSha256
)
$ErrorActionPreference = 'Stop'
$Archive = [IO.Path]::GetFullPath($Archive)
$stageName = 'DVielleStage-' + [Guid]::NewGuid().ToString('N')
$diagnosticPath = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) ('Temp\' + $stageName + '.log')
$diagnosticReaderSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) { throw 'Candidate archive is missing.' }
# Snapshot the reviewed bootstrap into the command line. Never elevate a script
# filename from writable storage and subsequently try to validate its contents.
$bootstrap = @'
$ErrorActionPreference = 'Stop'
try {
$env:PSModulePath = [IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::System),'WindowsPowerShell\v1.0\Modules')
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator token required.' }
function Assert-ProtectedObject {
    param([string]$Path, [switch]$Ancestor)
    $item = New-Object IO.DirectoryInfo($Path)
    if (-not $item.Exists -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe stage ancestor or target.' }
    $acl = $item.GetAccessControl()
    $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'Untrusted stage owner.' }
    $mask = if ($Ancestor) { 0x000D0150 } else { 0x000D0156 }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ([int]$rule.FileSystemRights -band $mask) -and $rule.IdentityReference.Value -notin $trusted) { throw 'Untrusted stage writer.' }
    }
}
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$cursor = $programFiles
while ($cursor) {
    Assert-ProtectedObject $cursor -Ancestor
    $parent = [IO.Path]::GetDirectoryName($cursor.TrimEnd('\'))
    if ($parent -eq $cursor) { break }
    $cursor = $parent
}
$source = [IO.File]::Open('__ARCHIVE__',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
$sha = [Security.Cryptography.SHA256]::Create()
try {
    if ($source.Length -gt 134217728) { throw 'Oversized archive.' }
    $digest = ([BitConverter]::ToString($sha.ComputeHash($source))).Replace('-','').ToLowerInvariant()
    if ($digest -cne '__DIGEST__') { throw 'Candidate archive does not match operator-approved digest.' }
    $source.Position = 0
    $null = [Reflection.Assembly]::LoadWithPartialName('System.IO.Compression')
    $zip = New-Object IO.Compression.ZipArchive($source,[IO.Compression.ZipArchiveMode]::Read,$true)
    try {
        if ($zip.Entries.Count -eq 0 -or $zip.Entries.Count -gt 5000) { throw 'Invalid archive entry count.' }
        $seen = @{}
        $total = [long]0
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            if ($entry.Length -gt 67108864 -or $name -match '[\\:*?"<>|]' -or $name.StartsWith('/') -or $name.EndsWith('/')) { throw 'Unsafe archive entry.' }
            foreach ($part in $name.Split('/')) {
                if (-not $part -or $part -in @('.','..') -or $part -match '[. ]$' -or $part -match '^(?i:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)') { throw 'Unsafe Windows archive path.' }
            }
            if ($seen.ContainsKey($name)) { throw 'Duplicate archive path.' }
            $seen[$name] = $true
            $total += $entry.Length
            if ($total -gt 536870912) { throw 'Archive expansion bound exceeded.' }
        }
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true,$false)
        $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
        foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
            $identitySid = New-Object Security.Principal.SecurityIdentifier($sid)
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($identitySid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
            $acl.AddAccessRule($rule)
        }
        $stage = [IO.Path]::Combine($programFiles,'__STAGE__')
        if ([IO.Directory]::Exists($stage) -or [IO.File]::Exists($stage)) { throw 'Stage already exists.' }
        $null = [IO.Directory]::CreateDirectory($stage,$acl)
        Assert-ProtectedObject $stage
        foreach ($entry in $zip.Entries) {
            $destination = [IO.Path]::GetFullPath([IO.Path]::Combine($stage,$entry.FullName.Replace('/','\')))
            if (-not $destination.StartsWith($stage + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Archive escaped the stage.' }
            $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
            $input = $entry.Open()
            $output = New-Object IO.FileStream($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try {
                $buffer = New-Object byte[] 65536
                $copied = [long]0
                while (($count = $input.Read($buffer,0,$buffer.Length)) -gt 0) {
                    $copied += $count
                    if ($copied -gt $entry.Length) { throw 'Archive decompression exceeded declared size.' }
                    $output.Write($buffer,0,$count)
                }
                if ($copied -ne $entry.Length) { throw 'Incomplete archive entry.' }
                $output.Flush($true)
            } finally { $output.Dispose(); $input.Dispose() }
        }
        Write-Output ('Protected local stage created: ' + $stage)
        Write-Output 'No payload code executed; no service started or firewall rule changed.'
    } finally { $zip.Dispose() }
} finally { $sha.Dispose(); $source.Dispose() }
} catch {
    $message = $_.Exception.ToString() + [Environment]::NewLine + $_.ScriptStackTrace
    # Diagnostic only: exclusive creation cannot overwrite an existing file.
        $logAcl = New-Object Security.AccessControl.FileSecurity
        $logAcl.SetAccessRuleProtection($true,$false)
        $logAcl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
        foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
            $logAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl','Allow')))
        }
        $logAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('__READER__')),'Read','Allow')))
    $log = New-Object IO.FileStream('__LOG__',[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::Read,4096,[IO.FileOptions]::None,$logAcl)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($message)
        $log.Write($bytes,0,$bytes.Length)
        $log.Flush($true)
    } finally { $log.Dispose() }
    exit 1
}
'@
$bootstrap = $bootstrap.Replace('__ARCHIVE__',$Archive.Replace("'","''")).Replace('__DIGEST__',$ApprovedSha256).Replace('__STAGE__',$stageName).Replace('__LOG__',$diagnosticPath.Replace("'","''")).Replace('__READER__',$diagnosticReaderSid)
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
$system = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
$powershell = Join-Path $system 'WindowsPowerShell\v1.0\powershell.exe'
$process = Start-Process -FilePath $powershell -WorkingDirectory $system -ArgumentList ('-NoProfile -NonInteractive -EncodedCommand ' + $encoded) -Verb RunAs -WindowStyle Hidden -Wait -PassThru
if ($process.ExitCode -ne 0) { throw ('Protected staging failed; exit code ' + $process.ExitCode + '. Diagnostic: ' + $diagnosticPath + '. No activation is claimed.') }
Write-Output ('Protected stage created: ' + (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) $stageName))
