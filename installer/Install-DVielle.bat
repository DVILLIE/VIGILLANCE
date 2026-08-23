@echo off
title DVielle Installer - DEEP VIGILLANCE
echo.
echo  ============================================
echo    DVIELLE - DEEP VIGILLANCE
echo    Installer requires Administrator approval
echo  ============================================
echo.

:: Re-launch with UAC elevation on human click
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0install-dvielle.ps1\" -SourceRoot \"%~dp0..\"' -Verb RunAs -Wait"
    exit /b %errorLevel%
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-dvielle.ps1" -SourceRoot "%~dp0.."
pause
