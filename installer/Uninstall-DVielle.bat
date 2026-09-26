@echo off
setlocal
title DVielle Uninstaller
echo DVielle removal requires Administrator approval.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0elevate.ps1" -Operation Uninstall
set "DVIELLE_EXIT=%ERRORLEVEL%"
if not "%DVIELLE_EXIT%"=="0" echo Uninstall failed. Exit code: %DVIELLE_EXIT%
pause
exit /b %DVIELLE_EXIT%
