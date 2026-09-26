#Requires -Version 5.1
# Helpers only. Importing this file does not read host state or change Windows.
Set-StrictMode -Version Latest

function Assert-HardeningAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Applying or restoring hardening requires an Administrator PowerShell window.'
    }
}

function Get-HardeningHash {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Save-HardeningBackup {
    param($Backup, [string]$Path)
    $temporary = $Path + '.tmp'
    $Backup | Export-Clixml -LiteralPath $temporary -Depth 10
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function New-HardeningBackup {
    param([string]$Root)
    $folder = Join-Path $Root ('data\hardening\' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    $backup = [pscustomobject]@{
        Schema = 1
        Machine = $env:COMPUTERNAME
        UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        CreatedAt = [DateTime]::UtcNow.ToString('o')
        OperationId = [Guid]::NewGuid().ToString('N')
        Registry = @()
        Hosts = $null
        FirewallRules = @()
        Restored = $false
    }
    $path = Join-Path $folder 'backup.clixml'
    Save-HardeningBackup $backup $path
    return [pscustomobject]@{ Backup = $backup; Path = $path }
}

function Set-HardeningRegistryValue {
    param($Backup, [string]$BackupPath, [string]$Path, [string]$Name, [int]$Value)
    $keyExisted = Test-Path -LiteralPath $Path
    $existed = $false
    $oldValue = $null
    $oldKind = $null
    if ($keyExisted) {
        $key = Get-Item -LiteralPath $Path
        $existed = $key.GetValueNames() -contains $Name
        if ($existed) {
            $oldValue = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $oldKind = $key.GetValueKind($Name).ToString()
        }
    }
    $entry = [pscustomobject]@{
        Path = $Path; Name = $Name; KeyExisted = $keyExisted; Existed = $existed
        OldValue = $oldValue; OldKind = $oldKind; NewValue = $Value
    }
    $Backup.Registry = @($Backup.Registry) + $entry
    # Journal before mutation so an interrupted run remains reversible.
    Save-HardeningBackup $Backup $BackupPath
    # Registry New-Item -Force can erase every value in an existing key.
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -ErrorAction Stop | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    $written = Get-HardeningRegistryState $Path $Name
    if (-not $written.Exists -or $written.Kind -ne 'DWord' -or $written.Value -ne $Value) {
        throw "Registry verification failed for $Path\$Name. Backup: $BackupPath"
    }
}

function Get-HardeningRegistryState {
    param([string]$Path, [string]$Name)
    if (Test-Path -LiteralPath $Path) {
        $key = Get-Item -LiteralPath $Path
        if ($key.GetValueNames() -contains $Name) {
            return [pscustomobject]@{
                Exists = $true; Kind = $key.GetValueKind($Name).ToString()
                Value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        }
    }
    return [pscustomobject]@{ Exists = $false; Kind = $null; Value = $null }
}

function Test-HardeningRegistryState {
    param($State, [bool]$Exists, $Kind, $Value)
    if ($State.Exists -ne $Exists) { return $false }
    if (-not $Exists) { return $true }
    if ($State.Kind -ne $Kind) { return $false }
    # Registry binary and multi-string values need content equality as well as kind equality.
    return ((ConvertTo-Json -InputObject $State.Value -Compress -Depth 4) -ceq
        (ConvertTo-Json -InputObject $Value -Compress -Depth 4))
}

function Assert-HardeningRegistryTarget {
    param([string]$Path, [string]$Name)
    $allowed = @{
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' = 'AllowTelemetry'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' = 'Enabled'
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' = 'PublishUserActivities'
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' = 'AllowCortana'
    }
    if (-not $allowed.ContainsKey($Path) -or $allowed[$Path] -ine $Name) {
        throw "Unexpected registry target in hardening backup: $Path\$Name"
    }
}

function Restore-HardeningBackup {
    param([string]$Path)
    Assert-HardeningAdmin
    $backup = Import-Clixml -LiteralPath $Path
    if ($backup.Schema -ne 1 -or $backup.OperationId -notmatch '^[a-f0-9]{32}$' -or $backup.Machine -ne $env:COMPUTERNAME -or
        $backup.UserSid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
        throw 'Backup must belong to this machine and the current Windows user.'
    }
    if ($backup.Restored) { Write-Host 'This backup was already restored.'; return }
    # Validate all restoration targets BEFORE changing any target. Never clobber later edits.
    if ($backup.Hosts) {
        $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        if ([IO.Path]::GetFullPath($backup.Hosts.Path) -ine $hostsPath -or
            (Get-HardeningHash ([Convert]::FromBase64String($backup.Hosts.BeforeBase64))) -ne $backup.Hosts.BeforeHash) {
            throw 'Invalid hosts target or damaged hosts content in hardening backup.'
        }
        $currentHash = Get-HardeningHash ([IO.File]::ReadAllBytes($backup.Hosts.Path))
        if ($currentHash -ne $backup.Hosts.BeforeHash -and $currentHash -ne $backup.Hosts.AfterHash) {
            throw 'Hosts changed since hardening. Merge the saved hosts backup manually; automatic restore refused.'
        }
    }
    foreach ($entry in @($backup.Registry)) {
        Assert-HardeningRegistryTarget $entry.Path $entry.Name
        $current = Get-HardeningRegistryState $entry.Path $entry.Name
        $isApplied = Test-HardeningRegistryState $current $true 'DWord' $entry.NewValue
        $isOriginal = Test-HardeningRegistryState $current $entry.Existed $entry.OldKind $entry.OldValue
        if (-not $isApplied -and -not $isOriginal) {
            throw "Registry changed since hardening: $($entry.Path)\$($entry.Name). Automatic restore refused."
        }
    }
    foreach ($ruleName in @($backup.FirewallRules)) {
        $prefix = 'DVielle-Telemetry-' + $backup.OperationId + '-'
        $programName = $ruleName.Substring([Math]::Min($prefix.Length, $ruleName.Length))
        if (-not $ruleName.StartsWith($prefix, [StringComparison]::Ordinal) -or
            $programName -cnotin @('CompatTelRunner.exe', 'DeviceCensus.exe')) {
            throw "Unexpected firewall target in hardening backup: $ruleName"
        }
        $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        if ($rule) {
            $filter = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
            if ($rule.Group -ne 'DVielle-TelemetryBlock' -or $rule.Description -ne ('DVielle backup ' + $backup.OperationId) -or
                $rule.Direction -ne 'Outbound' -or $rule.Action -ne 'Block' -or
                $filter.Program -ine (Join-Path $env:SystemRoot ('System32\' + $programName))) {
                throw "Firewall rule ownership or scope changed: $ruleName. Automatic restore refused."
            }
        }
    }
    foreach ($ruleName in @($backup.FirewallRules)) {
        $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        if ($rule) {
            $rule | Remove-NetFirewallRule -ErrorAction Stop
            if (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue) { throw "Firewall removal failed: $ruleName" }
        }
    }
    if ($backup.Hosts) {
        [IO.File]::WriteAllBytes($backup.Hosts.Path, [Convert]::FromBase64String($backup.Hosts.BeforeBase64))
        if ((Get-HardeningHash ([IO.File]::ReadAllBytes($backup.Hosts.Path))) -ne $backup.Hosts.BeforeHash) {
            throw 'Restored hosts verification failed. The backup remains unrestored for retry.'
        }
    }
    foreach ($entry in @($backup.Registry)) {
        if ($entry.Existed) {
            if (-not (Test-Path -LiteralPath $entry.Path)) { New-Item -Path $entry.Path -ErrorAction Stop | Out-Null }
            New-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -Value $entry.OldValue -PropertyType $entry.OldKind -Force | Out-Null
        } elseif (Test-Path -LiteralPath $entry.Path) {
            $current = Get-HardeningRegistryState $entry.Path $entry.Name
            if ($current.Exists) { Remove-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -ErrorAction Stop }
        }
        $restored = Get-HardeningRegistryState $entry.Path $entry.Name
        if (-not (Test-HardeningRegistryState $restored $entry.Existed $entry.OldKind $entry.OldValue)) {
            throw "Registry restore verification failed: $($entry.Path)\$($entry.Name)"
        }
        # Leave newly created empty keys: removing a key could remove another application's values.
    }
    $backup.Restored = $true
    Save-HardeningBackup $backup $Path
    Write-Host "Restored saved registry values, hosts content, and DVielle firewall changes from $Path."
}

function Test-IsUpdateSafe {
    param([string]$Domain)
    $value = $Domain.Trim().ToLowerInvariant().TrimEnd('.')
    foreach ($safe in @('windowsupdate.com', 'update.microsoft.com', 'download.microsoft.com', 'delivery.mp.microsoft.com', 'mp.microsoft.com',
        'wns.windows.com', 'login.live.com', 'login.microsoftonline.com', 'settings-win.data.microsoft.com')) {
        if ($value -eq $safe -or $value.EndsWith('.' + $safe)) { return $true }
    }
    return $false
}

function Get-TelemetryDomains {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing domain list: $Path" }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $domain = ($line -split '#', 2)[0].Trim().ToLowerInvariant().TrimEnd('.')
        if (-not $domain) { continue }
        if ($domain -notmatch '^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') {
            throw "Invalid domain list entry: $domain"
        }
        if (-not (Test-IsUpdateSafe $domain)) { $domain }
    }
}

function Get-ManagedHostsContent {
    param([string]$Content, [string[]]$Domains)
    # Replace only contiguous entries under DVielle's own old/new markers.
    $output = New-Object System.Collections.Generic.List[string]
    $managed = $false
    foreach ($line in ($Content -split '\r?\n')) {
        if ($line.Trim() -in @('# DVielle telemetry block', '# Fortoro Agent telemetry block', '# BEGIN DVielle telemetry block')) {
            $managed = $true
            continue
        }
        if ($line.Trim() -eq '# END DVielle telemetry block') { $managed = $false; continue }
        if ($managed -and $line -match '^\s*0\.0\.0\.0\s+[a-zA-Z0-9.-]+\s*$') { continue }
        # An unexpected comment, blank, or non-block line ends a legacy section.
        $managed = $false
        $output.Add($line)
    }
    # The split preserves a trailing empty line; do not accumulate it on every update.
    while ($output.Count -gt 0 -and $output[$output.Count - 1] -eq '') { $output.RemoveAt($output.Count - 1) }
    $output.Add('# BEGIN DVielle telemetry block')
    foreach ($domain in @($Domains | Sort-Object -Unique)) { $output.Add("0.0.0.0 $domain") }
    $output.Add('# END DVielle telemetry block')
    return (($output -join "`r`n").TrimEnd("`r", "`n") + "`r`n")
}

function Set-HardeningHosts {
    param($Backup, [string]$BackupPath, [string[]]$Domains)
    $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $before = [IO.File]::ReadAllBytes($path)
    # Preserve UTF-8/UTF-16 BOM encodings. Unmarked Windows hosts files use ANSI.
    $offset = 0
    $encoding = [Text.Encoding]::Default
    if ($before.Length -ge 3 -and $before[0] -eq 239 -and $before[1] -eq 187 -and $before[2] -eq 191) {
        $encoding = New-Object Text.UTF8Encoding($true); $offset = 3
    } elseif ($before.Length -ge 2 -and $before[0] -eq 255 -and $before[1] -eq 254) {
        $encoding = [Text.Encoding]::Unicode; $offset = 2
    } elseif ($before.Length -ge 2 -and $before[0] -eq 254 -and $before[1] -eq 255) {
        $encoding = [Text.Encoding]::BigEndianUnicode; $offset = 2
    }
    $content = $encoding.GetString($before, $offset, $before.Length - $offset)
    $replacement = Get-ManagedHostsContent $content $Domains
    [byte[]]$after = @($encoding.GetPreamble()) + @($encoding.GetBytes($replacement))
    $Backup.Hosts = [pscustomobject]@{
        Path = $path; BeforeBase64 = [Convert]::ToBase64String($before)
        BeforeHash = (Get-HardeningHash $before); AfterHash = (Get-HardeningHash $after)
    }
    Save-HardeningBackup $Backup $BackupPath
    [IO.File]::WriteAllBytes($path, $after)
    if ((Get-HardeningHash ([IO.File]::ReadAllBytes($path))) -ne $Backup.Hosts.AfterHash) {
        throw "Hosts verification failed. Backup: $BackupPath"
    }
}

function Add-HardeningFirewallRules {
    param($Backup, [string]$BackupPath)
    $count = 0
    # Separate explicit opt-in: keep Windows Search, error reporting and other apps intact.
    foreach ($name in @('CompatTelRunner.exe', 'DeviceCensus.exe')) {
        $program = Join-Path $env:SystemRoot ('System32\' + $name)
        if (-not (Test-Path -LiteralPath $program -PathType Leaf)) { continue }
        $ruleName = 'DVielle-Telemetry-' + $Backup.OperationId + '-' + $name
        $Backup.FirewallRules = @($Backup.FirewallRules) + $ruleName
        Save-HardeningBackup $Backup $BackupPath
        New-NetFirewallRule -Name $ruleName -DisplayName ('DVielle telemetry: ' + $name) -Group 'DVielle-TelemetryBlock' -Description ('DVielle backup ' + $Backup.OperationId) -Direction Outbound -Program $program -Action Block -Enabled True -Profile Any -ErrorAction Stop | Out-Null
        $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction Stop
        $filter = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
        if ($rule.Action -ne 'Block' -or $rule.Enabled -ne 'True' -or $rule.Direction -ne 'Outbound' -or $filter.Program -ine $program) {
            throw "Firewall verification failed for $name. Backup: $BackupPath"
        }
        $count++
    }
    Write-Host "Verified $count telemetry program firewall blocks."
}
