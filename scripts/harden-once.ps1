#Requires -Version 5.1
<# Preview by default. Use -Apply after reviewing the displayed scope. No AppX packages are removed. #>
param(
    [switch]$Apply,
    [switch]$SkipRestorePoint,
    [switch]$SkipHosts,
    [switch]$SkipBloatware,
    [switch]$DisableCortana,
    [switch]$BlockTelemetryPrograms,
    [string]$RestoreFrom
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'hardening-common.ps1')
if ($RestoreFrom) {
    Write-Host "Restore saved DVielle hardening changes from: $RestoreFrom"
    if (-not $Apply) { Write-Host 'Preview only. Add -Apply to restore.'; return }
    Restore-HardeningBackup $RestoreFrom
    return
}
$root = Split-Path -Parent $PSScriptRoot
$edition = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID).EditionID
# Diagnostic data off is supported on Enterprise, Education, and Server; Home/Pro use Required.
$telemetry = 1
if ($edition -match '^(Enterprise|Education|IoTEnterprise|Server)') { $telemetry = 0 }
$settings = @(
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Value = $telemetry },
    @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'; Name = 'Enabled'; Value = 0 },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'PublishUserActivities'; Value = 0 }
)
if ($DisableCortana) { $settings += @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name = 'AllowCortana'; Value = 0 } }
$domains = @()
if (-not $SkipHosts) { $domains = @(Get-TelemetryDomains (Join-Path $root 'config\telemetry-domains.txt') | Sort-Object -Unique) }
Write-Host "Hardening plan for Windows edition $edition (AllowTelemetry=$telemetry)."
foreach ($setting in $settings) { Write-Host ("  {0}\{1} = {2}" -f $setting.Path, $setting.Name, $setting.Value) }
if (-not $SkipHosts) { Write-Host "  Replace DVielle's hosts block with $($domains.Count) reviewed domains:"; $domains | ForEach-Object { Write-Host "    $_" } }
if ($BlockTelemetryPrograms) { Write-Host '  Block outbound CompatTelRunner.exe and DeviceCensus.exe where present.' }
Write-Host 'No application packages, Windows Search, Update, Defender, or certificate settings will be removed.'
if ($SkipBloatware) { Write-Host '-SkipBloatware is retained for compatibility; no package removal is performed.' }
if (-not $Apply) { Write-Host 'Preview only. Re-run with -Apply after reviewing; no changes made.'; return }
Assert-HardeningAdmin
if (-not $SkipRestorePoint) {
    # A failed restore point is a hard stop; only the explicit switch opts out.
    Checkpoint-Computer -Description 'DVielle pre-hardening' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
}
$state = New-HardeningBackup $root
Write-Host "Reversible backup: $($state.Path)"
try {
    foreach ($setting in $settings) {
        Set-HardeningRegistryValue -Backup $state.Backup -BackupPath $state.Path @setting
    }
    if (-not $SkipHosts) { Set-HardeningHosts $state.Backup $state.Path $domains }
    if ($BlockTelemetryPrograms) { Add-HardeningFirewallRules $state.Backup $state.Path }
} catch {
    Write-Warning "Hardening stopped. Restore the recorded changes with: .\scripts\harden-once.ps1 -RestoreFrom '$($state.Path)' -Apply"
    throw
}
Write-Host 'Requested settings were written and verified. Effective diagnostic behavior depends on Windows policy; this does not mean zero Microsoft traffic.'
