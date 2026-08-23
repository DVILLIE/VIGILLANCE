#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory = $true)]
    [string]$IpAddress,
    [string]$Reason = "DVielle auto-block"
)

$ruleName = "DVielle-Block-$IpAddress"

$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Rule already exists for $IpAddress"
    exit 0
}

New-NetFirewallRule `
    -DisplayName $ruleName `
    -Description $Reason `
    -Direction Inbound `
    -RemoteAddress $IpAddress `
    -Action Block `
    -Enabled True `
    -Profile Any | Out-Null

Write-Host "Blocked inbound from $IpAddress"
