#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Block Microsoft telemetry: hosts file + outbound firewall for telemetry executables.
    Windows Update / delivery / certificate endpoints are never blocked.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$DomainsFile
)

$ErrorActionPreference = "SilentlyContinue"
$RuleGroup = "DVielle-TelemetryBlock"
$LegacyRuleGroup = "FortoroAgent-TelemetryBlock"
$DVielleMarker = "# DVielle telemetry block"
$LegacyMarker = "# Fortoro Agent telemetry block"

# Must never block — Update, delivery, CRL / certificate trust
$UpdateSafe = @(
    "download.windowsupdate.com",
    "update.microsoft.com",
    "windowsupdate.com",
    "ctldl.windowsupdate.com",
    "fe2cr.update.microsoft.com",
    "fe3cr.delivery.mp.microsoft.com",
    "delivery.mp.microsoft.com",
    "dl.delivery.mp.microsoft.com",
    "wns.windows.com",
    "login.live.com",
    "login.microsoftonline.com"
)

# Substring patterns also skipped when matching domain lines
$UpdateSafeSuffixes = @(
    ".windowsupdate.com",
    ".update.microsoft.com",
    ".delivery.mp.microsoft.com",
    ".mp.microsoft.com"
)

function Test-IsUpdateSafe([string]$domain) {
    $d = $domain.Trim().ToLower()
    if ($UpdateSafe -contains $d) { return $true }
    foreach ($suf in $UpdateSafeSuffixes) {
        if ($d.EndsWith($suf) -or $d -eq $suf.TrimStart('.')) { return $true }
    }
    return $false
}

# Remove legacy Fortoro firewall rules
Get-NetFirewallRule -DisplayName "$LegacyRuleGroup-*" -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

# 1. Hosts file — block telemetry domains at DNS level
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $DomainsFile) {
    $content = Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue
    if ($content -notlike "*$DVielleMarker*" -and $content -notlike "*$LegacyMarker*") {
        Add-Content -Path $hostsPath -Value "`n$DVielleMarker"
        Get-Content $DomainsFile | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object {
            $d = $_.Trim().ToLower()
            if ($d -and -not (Test-IsUpdateSafe $d)) {
                Add-Content -Path $hostsPath -Value "0.0.0.0 $d"
            }
        }
        Write-Host "Hosts file telemetry blocks applied."
    } else {
        Write-Host "Hosts telemetry marker already present — skipped."
    }
}

# 2. Firewall — block outbound from known telemetry executables only
$telemetryPrograms = @(
    "$env:SystemRoot\System32\CompatTelRunner.exe",
    "$env:SystemRoot\System32\DeviceCensus.exe",
    "$env:SystemRoot\System32\dmclient.exe",
    "$env:SystemRoot\System32\wermgr.exe",
    "$env:SystemRoot\SystemApps\Microsoft.Windows.Search_*"
)

Get-NetFirewallRule -DisplayName "$RuleGroup-*" -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

$count = 0
foreach ($pattern in $telemetryPrograms) {
    $files = @()
    if ($pattern -like '*`**') {
        $files = Get-ChildItem -Path ($pattern -replace '\\[^\\]*$','') -Filter ($pattern.Split('\')[-1]) -ErrorAction SilentlyContinue
    } elseif (Test-Path $pattern) {
        $files = @(Get-Item $pattern)
    }
    foreach ($file in $files) {
        $safeName = ($file.Name -replace '[^a-zA-Z0-9]', '_').Substring(0, [Math]::Min(40, ($file.Name -replace '[^a-zA-Z0-9]', '_').Length))
        New-NetFirewallRule `
            -DisplayName "$RuleGroup-$safeName" `
            -Description "DVielle: block telemetry uploads from $($file.Name)" `
            -Direction Outbound `
            -Program $file.FullName `
            -Action Block `
            -Enabled True `
            -Profile Any | Out-Null
        $count++
    }
}

Write-Host "Applied $count telemetry program firewall blocks."
Write-Host "Windows Update / delivery / CRL domains were NOT blocked."
