#Requires -Version 5.1
# Functions only: safe to load for validation without changing the machine.
Set-StrictMode -Version Latest

function Test-DvielleAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-DvielleNative {
    param([Parameter(Mandatory)][string]$Executable, [string[]]$Arguments = @())
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Executable failed with exit code $LASTEXITCODE. Installation stopped."
    }
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
    return ($working -ieq $Root -and $action.Arguments -match '^\s*-m\s+(agent\.main|dvielle)\s*$' -and
        [IO.Path]::GetFileName($action.Execute) -match '^pythonw?\.exe$')
}

function Get-DvielleOwnedProcesses {
    param([string]$Root)
    $pythonDir = Join-Path $Root '.venv\Scripts'
    Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $_.ExecutablePath -and $_.CommandLine -and
        [IO.Path]::GetDirectoryName($_.ExecutablePath) -ieq $pythonDir -and
        $_.CommandLine -match '(?:^|\s)-m\s+(?:agent\.main|dvielle)(?:\s|$)'
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
        throw ('Legacy or external DVielle Python processes detected (PID ' +
            (($legacy | ForEach-Object { $_.ProcessId }) -join ', ') +
            '). Exit those instances before installing or uninstalling. Their ownership is ambiguous; none were killed.')
    }
    $python = Join-Path $Root '.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $python) {
        Push-Location $Root
        try {
            Invoke-DvielleNative $python @('-m', 'agent.main', '--stop', '--config-dir', (Join-Path $Root 'config'))
        } finally { Pop-Location }
    }
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
        throw 'DVielle windows are still running. Exit DVielle from its tray menu, then retry. No process was force-killed.'
    }
    foreach ($name in @('DVielle', 'DVielleGUI')) {
        $task = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
        if ($task -and -not (Test-DvielleTaskOwner $task $Root)) {
            throw "Task $name belongs to another installation; refusing to modify it."
        }
        if ($task -and $task.State -eq 'Running') {
            throw "Task $name is still running. Stop it through DVielle before reinstalling or uninstalling."
        }
    }
}
