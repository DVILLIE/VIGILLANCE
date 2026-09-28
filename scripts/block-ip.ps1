#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Operator-only inbound firewall helper. Not a DVielle product protection guarantee.

.DESCRIPTION
    The resident agent and DualGate do not call this script. A matching display
    name is not protection. Exit 0 only after the live rule is Block, Inbound,
    Enabled, and its remote address is the requested IP. Otherwise exit 1 and
    do not claim the address is blocked.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$IpAddress,
    [string]$Reason = "DVielle operator block"
)

$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'installer\common.ps1')

$ruleName = "DVielle-Block-$IpAddress"
$existing = @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)
$verified = @($existing | Where-Object { Test-DvielleBlockCoversAddress $_ $IpAddress })
if ($verified.Count -ge 1) {
    Write-Host "Verified existing inbound block for $IpAddress"
    exit 0
}
if ($existing.Count -ge 1) {
    Write-Error "A rule named $ruleName exists but does not block $IpAddress. Not protected."
    exit 1
}

try {
    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Description $Reason `
        -Direction Inbound `
        -RemoteAddress $IpAddress `
        -Action Block `
        -Enabled True `
        -Profile Any | Out-Null
} catch {
    Write-Error "Firewall rule creation failed for $IpAddress. Not protected. $_"
    exit 1
}

$created = @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)
$ok = @($created | Where-Object { Test-DvielleBlockCoversAddress $_ $IpAddress })
if ($ok.Count -lt 1) {
    Write-Error "Rule creation was not verified for $IpAddress. Not protected."
    exit 1
}
Write-Host "Verified inbound block for $IpAddress"
exit 0
