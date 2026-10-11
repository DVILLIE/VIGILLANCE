@echo off
setlocal
title D'Vielle Installer - Intelligent Vigilance
echo D'Vielle installation requires Administrator approval.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0elevate.ps1" -Operation Install
set "DVIELLE_EXIT=%ERRORLEVEL%"
if not "%DVIELLE_EXIT%"=="0" (
  echo Installation failed. Exit code: %DVIELLE_EXIT%
  pause
)
exit /b %DVIELLE_EXIT%
