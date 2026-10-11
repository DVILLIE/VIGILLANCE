#Requires -Version 5.1
# Functions only: safe to load for validation without changing the machine.
Set-StrictMode -Version Latest

function Test-DvielleAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DvielleTrustedPython312 {
    # Resolve a real executable before any version probe. The py launcher can
    # select a user-writable interpreter; never execute it elevated to discover
    # that path. Isolated Python ignores PYTHONPATH and user site packages.
    foreach ($candidate in @('python3.12', 'python')) {
        try {
            $command = Get-Command $candidate -CommandType Application -ErrorAction Stop
            $program = $command.Source
            Assert-DvielleTrustedExecutionTree (Split-Path -Parent $program)
            $result = & $program -I -c 'import sys; print(sys.executable); sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)' 2>$null
            if ($LASTEXITCODE -eq 0 -and $result -and (Test-Path -LiteralPath ([string]$result).Trim())) {
                return ([string]$result).Trim()
            }
        } catch { continue }
    }
    return $null
}

function Get-DvielleTrustedPython314 {
    $candidates = @((Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'DVielleRuntime\Python314\python.exe'))
    foreach ($name in @('python3.14', 'python')) {
        try { $candidates += (Get-Command $name -CommandType Application -ErrorAction Stop).Source } catch { }
    }
    foreach ($program in ($candidates | Select-Object -Unique)) {
        try {
            if (-not (Test-Path -LiteralPath $program -PathType Leaf)) { continue }
            Assert-DvielleTrustedExecutionTree $program
            $result = & $program -I -B -c 'import sys; print(sys.executable); sys.exit(0 if sys.version_info[:2] == (3,14) and sys.version_info[:3] >= (3,14,8) else 1)' 2>$null
            if ($LASTEXITCODE -eq 0 -and $result -and
                [IO.Path]::GetFullPath(([string]$result).Trim()) -ieq [IO.Path]::GetFullPath($program)) {
                return [IO.Path]::GetFullPath($program)
            }
        } catch { continue }
    }
    return $null
}

function Invoke-DvielleNative {
    param([Parameter(Mandatory)][string]$Executable, [string[]]$Arguments = @())
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Executable failed with exit code $LASTEXITCODE. Installation stopped."
    }
}

function Get-DvielleArtifactSha256 {
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose(); $stream.Dispose() }
}

function Assert-DvielleOfflineDependencies {
    param([Parameter(Mandatory)][string]$Bundle)
    $root = Resolve-DvielleRoot $Bundle
    Assert-DvielleTreeNoReparse $root $root
    $lock = Join-Path $root 'requirements.lock'
    $wheels = Join-Path $root 'wheels'
    if (-not (Test-Path -LiteralPath $lock -PathType Leaf) -or
        -not (Test-Path -LiteralPath $wheels -PathType Container)) { throw 'Missing offline dependency lock or wheel directory.' }
    if ((Get-Item -LiteralPath $lock).Length -gt 1048576) { throw 'Oversized dependency lock.' }
    $hashes = @{}
    $names = @{}
    foreach ($line in Get-Content -LiteralPath $lock) {
        if ($line -notmatch '^([a-z0-9]+(?:[-_.][a-z0-9]+)*)==([A-Za-z0-9.!+_-]+) --hash=sha256:([a-f0-9]{64})$') {
            throw 'Dependency lock must contain only exact versions and SHA256 hashes.'
        }
        $name = $Matches[1] -replace '[-_.]+', '-'
        $hash = $Matches[3]
        if ($names.ContainsKey($name) -or $hashes.ContainsKey($hash)) { throw 'Duplicate dependency pin.' }
        $names[$name] = $true
        $hashes[$hash] = $false
    }
    if ($hashes.Count -eq 0) { throw 'Empty dependency lock.' }
    foreach ($file in Get-ChildItem -LiteralPath $wheels -Force) {
        if ($file.PSIsContainer -or $file.Extension -cne '.whl') { throw 'Only wheel files may appear in the offline wheel directory.' }
        $hash = Get-DvielleArtifactSha256 $file.FullName
        if (-not $hashes.ContainsKey($hash) -or $hashes[$hash]) { throw 'Unlisted, duplicate or modified wheel artifact.' }
        $hashes[$hash] = $true
    }
    if (@($hashes.Values | Where-Object { -not $_ }).Count -ne 0) { throw 'Missing pinned wheel artifact.' }
}

function Get-DvielleSystemExecutable {
    param([Parameter(Mandatory)][ValidateSet('auditpol.exe', 'WindowsPowerShell\v1.0\powershell.exe')][string]$RelativePath)
    $systemDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    if (-not $systemDirectory) { throw 'The Windows System directory could not be identified.' }
    $program = Join-Path $systemDirectory $RelativePath
    Assert-DvielleTrustedExecutionTree $program
    return $program
}

function Resolve-DvielleRoot {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -notmatch '^[A-Za-z]:[\\/]') {
        throw "Install root must be an absolute local directory, not a drive-relative path: $Path"
    }
    $resolved = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($resolved -notmatch '^[A-Za-z]:\\' -or $resolved -eq [IO.Path]::GetPathRoot($resolved).TrimEnd('\')) {
        throw "Install root must be a local, non-root directory: $Path"
    }
    $protected = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
        $env:USERPROFILE, (Join-Path ([IO.Path]::GetPathRoot($resolved)) 'Users'),
        [Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('MyDocuments'))
    foreach ($directory in $protected) {
        if ($directory -and $resolved -ieq [IO.Path]::GetFullPath($directory).TrimEnd('\')) {
            throw "A shared Windows or user directory cannot be the installation root: $resolved"
        }
    }
    if ($env:SystemRoot -and $resolved.StartsWith($env:SystemRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Installing inside the Windows directory is not supported.'
    }
    # Reject junctions/symlinks at every existing ancestor, including the target.
    $cursor = $resolved
    while ($cursor -and (Split-Path -Parent $cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Reparse-point install paths are not supported: $cursor"
            }
        }
        $cursor = Split-Path -Parent $cursor
    }
    return $resolved
}

function Assert-DvielleTreeNoReparse {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Path)
    $safeRoot = Resolve-DvielleRoot $Root
    $target = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($target -ine $safeRoot -and -not $target.StartsWith($safeRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Filesystem target is outside the installation root: $target"
    }
    $null = Resolve-DvielleRoot $target
    if (-not (Test-Path -LiteralPath $target)) { return }
    # Walk one directory at a time so even Windows PowerShell 5.1 never follows a link.
    $pending = New-Object 'System.Collections.Generic.Queue[string]'
    $pending.Enqueue($target)
    while ($pending.Count -gt 0) {
        $current = Get-Item -LiteralPath $pending.Dequeue() -Force -ErrorAction Stop
        if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Reparse-point filesystem targets are not supported: $($current.FullName)"
        }
        if ($current.PSIsContainer) {
            foreach ($child in Get-ChildItem -LiteralPath $current.FullName -Force -ErrorAction Stop) {
                if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                    throw "Reparse-point filesystem targets are not supported: $($child.FullName)"
                }
                if ($child.PSIsContainer) { $pending.Enqueue($child.FullName) }
            }
        }
    }
}

function Disable-DvielleOwnedTasks {
    param([Parameter(Mandatory)][string]$Root)
    $owned = @()
    # Validate every task before disabling any task.
    foreach ($name in @('DVielle', 'DVielleGUI')) {
        $task = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
        if ($task) {
            if (-not (Test-DvielleTaskOwner $task $Root)) { throw "Task $name belongs to another installation." }
            $owned += $name
        }
    }
    foreach ($name in $owned) { Disable-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop | Out-Null }
}

function Test-DvielleTaskOwner {
    param($Task, [string]$Root)
    if (-not $Task -or @($Task.Actions).Count -ne 1) { return $false }
    $action = $Task.Actions[0]
    if ([string]::IsNullOrEmpty($action.WorkingDirectory)) { return $false }
    $working = [IO.Path]::GetFullPath($action.WorkingDirectory).TrimEnd('\')
    if ([string]::IsNullOrEmpty($action.Execute) -or $action.Execute -notmatch '^[A-Za-z]:[\\/]') { return $false }
    $executable = [IO.Path]::GetFullPath($action.Execute)
    $runtime = Join-Path $Root '.venv\Scripts'
    return ($working -ieq $Root -and $action.Arguments -match '^\s*-m\s+(agent\.main|dvielle)\s*$' -and
        ($executable -ieq (Join-Path $runtime 'python.exe') -or
         $executable -ieq (Join-Path $runtime 'pythonw.exe')))
}

function Get-DvielleOwnedProcesses {
    param([string]$Root)
    $pythonDir = Join-Path $Root '.venv\Scripts'
    $guiExe = Join-Path $pythonDir 'DVielle.exe'
    Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        if (-not $_.ExecutablePath -or -not $_.CommandLine) { return $false }
        $inScripts = [IO.Path]::GetDirectoryName($_.ExecutablePath) -ieq $pythonDir
        $isGuiShim = $_.ExecutablePath -ieq $guiExe
        if (-not ($inScripts -or $isGuiShim)) { return $false }
        if ($isGuiShim) {
            return ($_.CommandLine -match '(?:^|\s)-m\s+dvielle(?:\s|$)')
        }
        return ($_.CommandLine -match '(?:^|\s)-m\s+(?:agent\.main|dvielle)(?:\s|$)')
    }
}

function Stop-DvielleOwnedRuntime {
    param([string]$Root)
    # Older releases ran global Python without a lease. Their working directory
    # is not available from CIM, so require an operator close instead of guessing
    # ownership or launching a second collector alongside them.
    $pythonDir = Join-Path $Root '.venv\Scripts'
    $legacy = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $_.Name -match '^pythonw?\.exe$' -and $_.CommandLine -and
        $_.CommandLine -match '(?:^|\s)-m\s+(?:agent\.main|dvielle)(?:\s|$)' -and
        (-not $_.ExecutablePath -or [IO.Path]::GetDirectoryName($_.ExecutablePath) -ine $pythonDir)
    })
    if ($legacy.Count -gt 0) {
        throw ('Legacy or external D''Vielle Python processes detected (PID ' +
            (($legacy | ForEach-Object { $_.ProcessId }) -join ', ') +
            '). Exit those instances before installing or uninstalling. Their ownership is ambiguous; none were killed.')
    }
    # Never execute an old installation's interpreter or modules in this
    # Administrator process. A writable tree could have been replaced before
    # an upgrade/uninstall. Request GUI closure; require the user to exit any
    # remaining resident instance through its existing Limited session.
    # Closing a console window is a normal close request; never force-kill a PID.
    foreach ($owned in @(Get-DvielleOwnedProcesses $Root)) {
        $process = Get-Process -Id $owned.ProcessId -ErrorAction SilentlyContinue
        if ($process -and $process.Path -ieq $owned.ExecutablePath -and
            $process.StartTime.ToUniversalTime() -eq $owned.CreationDate.ToUniversalTime()) {
            $null = $process.CloseMainWindow()
        }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $remaining = @(Get-DvielleOwnedProcesses $Root)
        if ($remaining.Count -eq 0) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($remaining.Count -gt 0) {
        throw 'D''Vielle windows are still running. Exit D''Vielle from its tray menu, then retry. No process was force-killed.'
    }
    foreach ($name in @('DVielle', 'DVielleGUI')) {
        $task = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
        if ($task -and -not (Test-DvielleTaskOwner $task $Root)) {
            throw "Task $name belongs to another installation; refusing to modify it."
        }
        if ($task -and $task.State -eq 'Running') {
            throw "Task $name is still running. Stop it through D'Vielle before reinstalling or uninstalling."
        }
    }
}

# Highest scheduled tasks run with the caller's elevated token
# (TASK_RUNLEVEL_HIGHEST). Only Administrators (S-1-5-32-544) and SYSTEM
# (S-1-5-18) may write the install tree. Authenticated Users (S-1-5-11) and
# Users (S-1-5-32-545) receive ReadAndExecute. Any other write ACE fails closed.
# https://learn.microsoft.com/en-us/windows/win32/taskschd/principal-runlevel
# https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks

function New-DvielleElevationRule {
    param(
        [Parameter(Mandatory)][string]$Sid,
        [Parameter(Mandatory)][string]$Rights,
        [switch]$Directory
    )
    $id = New-Object System.Security.Principal.SecurityIdentifier $Sid
    $access = [System.Security.AccessControl.FileSystemRights]$Rights
    $type = [System.Security.AccessControl.AccessControlType]::Allow
    if ($Directory) {
        $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $none = [System.Security.AccessControl.PropagationFlags]::None
        return New-Object System.Security.AccessControl.FileSystemAccessRule($id, $access, $inherit, $none, $type)
    }
    return New-Object System.Security.AccessControl.FileSystemAccessRule($id, $access, $type)
}

function Get-DvielleElevationAcl {
    param([switch]$Directory)
    if ($Directory) {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
    } else {
        $acl = New-Object System.Security.AccessControl.FileSecurity
    }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
    # Nested arrays flatten inside @(). Objects keep each SID with its rights.
    $grants = @(
        [pscustomobject]@{ Sid = 'S-1-5-32-544'; Rights = 'FullControl' }
        [pscustomobject]@{ Sid = 'S-1-5-18'; Rights = 'FullControl' }
        [pscustomobject]@{ Sid = 'S-1-5-11'; Rights = 'ReadAndExecute' }
        [pscustomobject]@{ Sid = 'S-1-5-32-545'; Rights = 'ReadAndExecute' }
    )
    foreach ($grant in $grants) {
        $acl.AddAccessRule((New-DvielleElevationRule -Sid $grant.Sid -Rights $grant.Rights -Directory:$Directory))
    }
    return $acl
}

function ConvertTo-DvielleSid {
    param($Identity)
    if ($null -eq $Identity) { return '' }
    if ($Identity -is [System.Security.Principal.SecurityIdentifier]) { return $Identity.Value }
    $text = [string]$Identity
    if ($text -match '^S-1-') { return $text }
    try {
        $account = New-Object System.Security.Principal.NTAccount $text
        return $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $text
    }
}

function Test-DvielleAclDeniesUserWrite {
    param($Acl, [switch]$Ancestor)
    if (-not $Acl) { return $false }
    # Composite Modify/FullControl masks include read bits. Compare only
    # individual mutation rights so ReadAndExecute remains read-only.
    $writeBits = [System.Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    if ($Ancestor) {
        # Creating a sibling is harmless; deleting/replacing this directory or
        # changing its permissions/owner can replace the protected descendant.
        $writeBits = [System.Security.AccessControl.FileSystemRights]'Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    }
    $trusted = @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    # An owner has implicit WRITE_DAC even when its ACE says ReadAndExecute.
    try { $ownerSid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value }
    catch { return $false }
    if ($ownerSid -notin $trusted) { return $false }
    $trustedWriter = $false
    foreach ($ace in @($Acl.Access)) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if ($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        $sid = ConvertTo-DvielleSid $ace.IdentityReference
        $hasWrite = ([int]$ace.FileSystemRights -band [int]$writeBits) -ne 0
        if ($hasWrite) {
            if ($sid -notin $trusted) { return $false }
            $trustedWriter = $true
        }
    }
    # Windows Resource Protection files may grant maintenance write only to
    # TrustedInstaller while Administrators and SYSTEM receive read/execute.
    return $trustedWriter
}

function Test-DvielleProtectedAncestors {
    param([Parameter(Mandatory)][string]$Path)
    $cursor = Split-Path -Parent ([IO.Path]::GetFullPath($Path).TrimEnd('\'))
    while ($cursor) {
        if (-not (Test-Path -LiteralPath $cursor -PathType Container)) { return $false }
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        if (-not (Test-DvielleAclDeniesUserWrite (Get-Acl -LiteralPath $cursor) -Ancestor)) { return $false }
        $parent = Split-Path -Parent $cursor
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    return $true
}

function Get-DviellePrivateRuntimeAcl {
    param([Parameter(Mandatory)][string]$UserSid, [switch]$Directory)
    if ($UserSid -notmatch '^S-1-(?:5-21|12-1)-\d+-\d+-\d+-\d+$') { throw 'One installed-user SID is required.' }
    if ($Directory) { $acl = New-Object System.Security.AccessControl.DirectorySecurity }
    else { $acl = New-Object System.Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier $UserSid))
    foreach ($grant in @(
        [pscustomobject]@{ Sid = 'S-1-5-32-544'; Rights = 'FullControl' }
        [pscustomobject]@{ Sid = 'S-1-5-18'; Rights = 'FullControl' }
        [pscustomobject]@{ Sid = $UserSid; Rights = 'Modify' }
    )) {
        $acl.AddAccessRule((New-DvielleElevationRule -Sid $grant.Sid -Rights $grant.Rights -Directory:$Directory))
    }
    return $acl
}

function Test-DviellePrivateRuntimeAcl {
    param($Acl, [Parameter(Mandatory)][string]$UserSid)
    if (-not $Acl -or $UserSid -notmatch '^S-1-(?:5-21|12-1)-\d+-\d+-\d+-\d+$') { return $false }
    $allowed = @('S-1-5-32-544', 'S-1-5-18', $UserSid)
    try { $ownerSid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value }
    catch { return $false }
    if ($ownerSid -notin $allowed) { return $false }
    $userWritable = $false
    foreach ($ace in @($Acl.Access)) {
        if ($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if ($ace.AccessControlType -ne 'Allow') { return $false }
        $sid = ConvertTo-DvielleSid $ace.IdentityReference
        # Private observations/configuration must not be readable by other users.
        if ($sid -notin $allowed) { return $false }
        $modify = [int][System.Security.AccessControl.FileSystemRights]::Modify
        if ($sid -eq $UserSid -and ([int]$ace.FileSystemRights -band $modify) -eq $modify) { $userWritable = $true }
    }
    return $userWritable
}

function Assert-DviellePrivateRuntimeTree {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$UserSid)
    $pending = New-Object 'System.Collections.Generic.Queue[string]'
    $pending.Enqueue($Path)
    while ($pending.Count -gt 0) {
        $item = Get-Item -LiteralPath $pending.Dequeue() -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            -not (Test-DviellePrivateRuntimeAcl (Get-Acl -LiteralPath $item.FullName) $UserSid)) {
            throw "The private runtime tree has an unsafe ACL or reparse point: $($item.FullName)"
        }
        if ($item.PSIsContainer) {
            foreach ($child in Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop) { $pending.Enqueue($child.FullName) }
        }
    }
}

function Set-DviellePrivateRuntimeTree {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Relative,
          [Parameter(Mandatory)][string]$UserSid)
    if ($Relative -notin @('data', 'config')) { throw 'Only data and config may be private runtime subtrees.' }
    $target = Join-Path $Root $Relative
    Assert-DvielleTreeNoReparse $Root $target
    if (-not (Test-Path -LiteralPath $target -PathType Container)) { throw "Private runtime directory is missing: $target" }
    try {
        Assert-DviellePrivateRuntimeTree $target $UserSid
        return  # Never rewrite ACLs through an already user-mutable tree.
    } catch {
        # Only a new, still protected tree may be converted to private data.
        # Reject rather than recursively "repair" a user-writable old tree.
        Assert-DvielleTrustedExecutionTree $target
    }
    $pending = New-Object 'System.Collections.Generic.Queue[string]'
    $ordered = New-Object 'System.Collections.Generic.List[object]'
    $pending.Enqueue($target)
    while ($pending.Count -gt 0) {
        $item = Get-Item -LiteralPath $pending.Dequeue() -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'A private runtime path changed into a reparse point.' }
        $ordered.Add($item)
        if ($item.PSIsContainer) {
            foreach ($child in Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop) { $pending.Enqueue($child.FullName) }
        }
    }
    # Grant directories after their descendants, with the top root last.
    # Once a subtree is user-mutable, no elevated ACL write follows inside it.
    for ($index = $ordered.Count - 1; $index -ge 0; $index--) {
        $item = $ordered[$index]
        Set-Acl -LiteralPath $item.FullName -AclObject (Get-DviellePrivateRuntimeAcl $UserSid -Directory:([bool]$item.PSIsContainer))
    }
    Assert-DviellePrivateRuntimeTree $target $UserSid
}

function Assert-DvielleTrustedExecutionTree {
    param([Parameter(Mandatory)][string]$Path, [string]$RuntimePrivateSid)
    $target = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not (Test-DvielleProtectedAncestors $target)) {
        throw "Refusing elevated execution: an ancestor can replace the execution tree: $target"
    }
    $pending = New-Object 'System.Collections.Generic.Queue[string]'
    $pending.Enqueue($target)
    while ($pending.Count -gt 0) {
        $current = Get-Item -LiteralPath $pending.Dequeue() -Force -ErrorAction Stop
        if ($RuntimePrivateSid -and $current.PSIsContainer -and
            $current.FullName -in @((Join-Path $target 'data'), (Join-Path $target 'config'))) {
            # Exact allowlisted subtrees only. They are private, never trusted
            # as executable trees or as privileged approval/service state.
            Assert-DviellePrivateRuntimeTree $current.FullName $RuntimePrivateSid
            continue
        }
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            -not (Test-DvielleAclDeniesUserWrite (Get-Acl -LiteralPath $current.FullName))) {
            throw "Refusing elevated execution of an untrusted owner, writable object, or reparse point: $($current.FullName)"
        }
        if ($current.PSIsContainer) {
            foreach ($child in Get-ChildItem -LiteralPath $current.FullName -Force -ErrorAction Stop) {
                $pending.Enqueue($child.FullName)
            }
        }
    }
}

function Test-DvielleElevatedTree {
    param([Parameter(Mandatory)][string]$Root)
    $root = Resolve-DvielleRoot $Root
    try { Assert-DvielleTrustedExecutionTree $root } catch { return $false }
    foreach ($relative in @('agent\main.py', '.venv\Scripts\python.exe', '.venv\Scripts\pythonw.exe', '.venv\Scripts\DVielle.exe')) {
        $path = Join-Path $root $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }
        if (-not (Test-DvielleAclDeniesUserWrite (Get-Acl -LiteralPath $path))) { return $false }
    }
    $site = Join-Path $root '.venv\Lib\site-packages'
    if (Test-Path -LiteralPath $site) {
        if (-not (Test-DvielleAclDeniesUserWrite (Get-Acl -LiteralPath $site))) { return $false }
    }
    return (Test-DvielleAclDeniesUserWrite (Get-Acl -LiteralPath $root))
}

function Protect-DvielleInstallForElevation {
    param([Parameter(Mandatory)][string]$Root)
    if (-not (Test-DvielleAdmin)) { return $false }
    $root = Resolve-DvielleRoot $Root
    if (-not (Test-DvielleProtectedAncestors $root)) { return $false }
    foreach ($relative in @('agent\main.py', '.venv\Scripts\python.exe', '.venv\Scripts\pythonw.exe', '.venv\Scripts\DVielle.exe')) {
        if (-not (Test-Path -LiteralPath (Join-Path $root $relative) -PathType Leaf)) { return $false }
    }
    $pending = New-Object System.Collections.Generic.Queue[string]
    $pending.Enqueue($root)
    while ($pending.Count -gt 0) {
        $currentPath = $pending.Dequeue()
        $current = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
        if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        try {
            if ($current.PSIsContainer) {
                Set-Acl -LiteralPath $current.FullName -AclObject (Get-DvielleElevationAcl -Directory)
                foreach ($child in Get-ChildItem -LiteralPath $current.FullName -Force -ErrorAction Stop) {
                    if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
                    $pending.Enqueue($child.FullName)
                }
            } else {
                Set-Acl -LiteralPath $current.FullName -AclObject (Get-DvielleElevationAcl)
            }
        } catch {
            return $false
        }
        if (-not (Test-DvielleAclDeniesUserWrite (Get-Acl -LiteralPath $current.FullName))) { return $false }
    }
    return (Test-DvielleElevatedTree -Root $root)
}

function Test-DvielleBlockCoversAddress {
    param($Rule, [Parameter(Mandatory)][string]$IpAddress)
    if (-not $Rule) { return $false }
    if ([string]$Rule.Action -ne 'Block' -or [string]$Rule.Direction -ne 'Inbound') { return $false }
    if ([string]$Rule.Enabled -notin @('True', '1')) { return $false }
    $addresses = @()
    if ($Rule.PSObject.Properties.Name -contains 'RemoteAddress') {
        $addresses = @($Rule.RemoteAddress)
    } else {
        $filter = $Rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        if ($filter) { $addresses = @($filter.RemoteAddress) }
    }
    foreach ($candidate in $addresses) {
        foreach ($part in ([string]$candidate -split ',')) {
            $part = $part.Trim()
            if ($part -ieq $IpAddress -or $part -ieq ($IpAddress + '/32') -or $part -ieq ($IpAddress + '/255.255.255.255')) {
                return $true
            }
        }
    }
    return $false
}
