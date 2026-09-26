@echo off
setlocal
cd /d "%~dp0.."
title DVielle - Deep Vigilance (debug)
if not exist ".venv\Scripts\python.exe" (
  echo DVielle's Python 3.12 environment is missing. Run Install-DVielle.bat first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m dvielle
set "DVIELLE_EXIT=%ERRORLEVEL%"
echo DVielle exited. Code=%DVIELLE_EXIT%
pause
exit /b %DVIELLE_EXIT%
