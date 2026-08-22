#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Block Microsoft telemetry: hosts file + outbound firewall for telemetry executables.
    Windows Update is preserved — your internet stays for you, not background uploads.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$DomainsFile
)

$ErrorActionPreference = "SilentlyContinue"
$RuleGroup = "FortoroAgent-TelemetryBlock"
$FortoroMarker = "# Fortoro Agent telemetry block"

$UpdateSafe = @(
    "download.windowsupdate.com", "update.microsoft.com", "windowsupdate.com",
    "ctldl.windowsupdate.com", "fe2cr.update.microsoft.com",
    "fe3cr.delivery.mp.microsoft.com"
)

# 1. Hosts file — block telemetry domains at DNS level
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $DomainsFile) {
    $content = Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue
    if ($content -notlike "*$FortoroMarker*") {
        Add-Content -Path $hostsPath -Value "`n$FortoroMarker"
        Get-Content $DomainsFile | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object {
            $d = $_.Trim().ToLower()
            if ($d -and ($UpdateSafe -notcontains $d)) {
                Add-Content -Path $hostsPath -Value "0.0.0.0 $d"
            }
        }
        Write-Host "Hosts file telemetry blocks applied."
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
            -Description "Fortoro: block telemetry uploads from $($file.Name)" `
            -Direction Outbound `
            -Program $file.FullName `
            -Action Block `
            -Enabled True `
            -Profile Any | Out-Null
        $count++
    }
}

Write-Host "Applied $count telemetry program firewall blocks."
Write-Host "Windows Update domains were NOT blocked."
