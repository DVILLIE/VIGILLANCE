#Requires -RunAsAdministrator
<#
.SYNOPSIS
    One-time Windows privacy hardening for Fortoro Agent.
.DESCRIPTION
    Creates a restore point, disables telemetry/Cortana/ad ID, removes common bloatware,
    and blocks telemetry domains in hosts file (with Windows Update whitelist preserved).
.NOTES
    Run manually once. The agent only monitors for drift afterward.
#>
param(
    [switch]$SkipRestorePoint,
    [switch]$SkipBloatware,
    [switch]$SkipHosts
)

$ErrorActionPreference = "Stop"
$FortoroMarker = "# Fortoro Agent telemetry block"

function Write-Step($msg) { Write-Host "[Fortoro] $msg" -ForegroundColor Cyan }

# 1. Restore point
if (-not $SkipRestorePoint) {
    Write-Step "Creating system restore point..."
    try {
        Checkpoint-Computer -Description "Fortoro Agent pre-hardening" -RestorePointType MODIFY_SETTINGS
        Write-Step "Restore point created."
    } catch {
        Write-Warning "Could not create restore point (enable System Protection): $_"
    }
}

# 2. Telemetry
Write-Step "Disabling telemetry..."
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord

# 3. Cortana
Write-Step "Disabling Cortana..."
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord

# 4. Advertising ID
Write-Step "Disabling advertising ID..."
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord

# 5. Activity history
Write-Step "Disabling activity history..."
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Type DWord

# 6. Bloatware (safe list)
if (-not $SkipBloatware) {
    Write-Step "Removing common bloatware AppX packages..."
    $bloatPatterns = @(
        "*3DBuilder*", "*SkypeApp*", "*Xbox*", "*ZuneVideo*", "*BingWeather*",
        "*GetHelp*", "*MicrosoftSolitaireCollection*", "*MixedReality*"
    )
    foreach ($pattern in $bloatPatterns) {
        Get-AppxPackage $pattern -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $pattern |
            Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }
}

# 7. Hosts file telemetry blocks
if (-not $SkipHosts) {
    Write-Step "Blocking telemetry domains (hosts + firewall)..."
    $blockScript = Join-Path $PSScriptRoot "block-telemetry-firewall.ps1"
    if (Test-Path $blockScript) {
        & $blockScript -DomainsFile (Join-Path $PSScriptRoot "..\config\telemetry-domains.txt")
    } else {
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $domainsFile = Join-Path $PSScriptRoot "..\config\telemetry-domains.txt"
        if (Test-Path $domainsFile) {
            $content = Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue
            if ($content -notlike "*$FortoroMarker*") {
                Add-Content -Path $hostsPath -Value "`n$FortoroMarker"
                Get-Content $domainsFile | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object {
                    Add-Content -Path $hostsPath -Value "0.0.0.0 $_"
                }
            }
        }
    }
}

Write-Step "Hardening complete. Reboot recommended."
Write-Host "The Fortoro agent will monitor these settings for drift." -ForegroundColor Green
