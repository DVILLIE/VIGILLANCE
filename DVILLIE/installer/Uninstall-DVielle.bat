@echo off
title DVielle Uninstaller
echo.
echo  ============================================
echo    DVIELLE — Uninstall
echo    Administrator approval required
echo  ============================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0uninstall-dvielle.ps1\"' -Verb RunAs -Wait"
    exit /b %errorLevel%
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall-dvielle.ps1"
pause
