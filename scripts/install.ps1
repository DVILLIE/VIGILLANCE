#Requires -RunAsAdministrator
<#
.SYNOPSIS
    DEPRECATED — redirects to installer\install-dvielle.ps1
.DESCRIPTION
    Legacy Fortoro/ProgramFiles path removed. Single install story: C:\DVILLIE
#>
param(
    [string]$InstallDir = "C:\DVILLIE"
)

Write-Host ""
Write-Host "  scripts\install.ps1 is deprecated." -ForegroundColor Yellow
Write-Host "  Use: installer\Install-DVielle.bat  (installs to C:\DVILLIE)" -ForegroundColor Cyan
Write-Host ""

$canonical = Join-Path (Split-Path -Parent $PSScriptRoot) "installer\install-dvielle.ps1"
if (-not (Test-Path $canonical)) {
    Write-Host "ERROR: Missing $canonical" -ForegroundColor Red
    exit 1
}

try { & $canonical -InstallDir $InstallDir; exit 0 }
catch { Write-Error $_; exit 1 }
