#Requires -Version 5.1
<# Preview by default; network hardening requires -Apply. Program blocks need an additional explicit opt-in. #>
param(
    [Parameter(Mandatory = $true)][string]$DomainsFile,
    [switch]$Apply,
    [switch]$BlockTelemetryPrograms,
    [switch]$SkipRestorePoint
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'hardening-common.ps1')
$domains = @(Get-TelemetryDomains $DomainsFile | Sort-Object -Unique)
Write-Host "Hosts plan: replace only DVielle's managed section with $($domains.Count) domains."
$domains | ForEach-Object { Write-Host "  $_" }
if ($BlockTelemetryPrograms) { Write-Host 'Optional outbound blocks: CompatTelRunner.exe and DeviceCensus.exe where present.' }
Write-Host 'Update, delivery, certificate, account, and settings-win.data.microsoft.com endpoints are excluded from this domain list.'
if (-not $Apply) { Write-Host 'Preview only. Add -Apply after reviewing.'; return }
Assert-HardeningAdmin
if (-not $SkipRestorePoint) { Checkpoint-Computer -Description 'DVielle pre-network-hardening' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop }
$state = New-HardeningBackup (Split-Path -Parent $PSScriptRoot)
Write-Host "Reversible backup: $($state.Path)"
try {
    Set-HardeningHosts $state.Backup $state.Path $domains
    if ($BlockTelemetryPrograms) { Add-HardeningFirewallRules $state.Backup $state.Path }
} catch { Write-Warning "Operation stopped. Restore using harden-once.ps1 -RestoreFrom '$($state.Path)' -Apply"; throw }
Write-Host 'Requested network changes verified. Effective network traffic has not been measured.'
