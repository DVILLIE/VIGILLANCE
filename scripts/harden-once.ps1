#Requires -RunAsAdministrator
<#
.SYNOPSIS
    One-time Windows privacy hardening for DVielle.
.DESCRIPTION
    Creates a restore point, reduces telemetry/Cortana/ad ID, removes common bloatware,
    and blocks telemetry domains (Windows Update / delivery / CRL allowlisted).
.NOTES
    Run manually once (Admin). Agent monitors for drift afterward.
    On Windows Home, AllowTelemetry cannot truly reach "Security (0)" — lowest real
    floor is Required (1). We set policy to 0 where Pro/Enterprise allow it;
    Home may still report Required. Never claim zero Microsoft traffic.
#>
param(
    [switch]$SkipRestorePoint,
    [switch]$SkipBloatware,
    [switch]$SkipHosts
)

$ErrorActionPreference = "Stop"
$DVielleMarker = "# DVielle telemetry block"
$LegacyMarker = "# Fortoro Agent telemetry block"

function Write-Step($msg) { Write-Host "[DVielle] $msg" -ForegroundColor Cyan }

# 1. Restore point
if (-not $SkipRestorePoint) {
    Write-Step "Creating system restore point..."
    try {
        Checkpoint-Computer -Description "DVielle pre-hardening" -RestorePointType MODIFY_SETTINGS
        Write-Step "Restore point created."
    } catch {
        Write-Warning "Could not create restore point (enable System Protection): $_"
    }
}

# 2. Telemetry — aspirational Security (0); Home floors at Required
Write-Step "Reducing diagnostic data (AllowTelemetry)..."
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

# 6. Logon-failure audit (Event 4625) — required for attacks module
Write-Step "Enabling logon-failure audit..."
try {
    & auditpol.exe /set /subcategory:"Logon" /failure:enable | Out-Null
} catch {
    Write-Warning "auditpol failed: $_"
}

# 7. Bloatware (safe list)
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

# 8. Hosts file telemetry blocks
if (-not $SkipHosts) {
    Write-Step "Blocking telemetry domains (hosts + firewall; Update allowlisted)..."
    $blockScript = Join-Path $PSScriptRoot "block-telemetry-firewall.ps1"
    if (Test-Path $blockScript) {
        & $blockScript -DomainsFile (Join-Path $PSScriptRoot "..\config\telemetry-domains.txt")
    } else {
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $domainsFile = Join-Path $PSScriptRoot "..\config\telemetry-domains.txt"
        $UpdateSafe = @(
            "download.windowsupdate.com", "update.microsoft.com", "windowsupdate.com",
            "ctldl.windowsupdate.com", "fe2cr.update.microsoft.com",
            "fe3cr.delivery.mp.microsoft.com", "delivery.mp.microsoft.com"
        )
        if (Test-Path $domainsFile) {
            $content = Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue
            if ($content -notlike "*$DVielleMarker*" -and $content -notlike "*$LegacyMarker*") {
                Add-Content -Path $hostsPath -Value "`n$DVielleMarker"
                Get-Content $domainsFile | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object {
                    $d = $_.Trim().ToLower()
                    if ($d -and ($UpdateSafe -notcontains $d)) {
                        Add-Content -Path $hostsPath -Value "0.0.0.0 $d"
                    }
                }
            }
        }
    }
}

Write-Step "Hardening complete. Reboot recommended."
Write-Host "DVielle will monitor these settings for drift. Home editions may still show Required diagnostic data." -ForegroundColor Green
