@echo off
setlocal
cd /d "%~dp0.."
title D'Vielle - Intelligent Vigilance (debug)
if not exist ".venv\Scripts\python.exe" (
  echo D'Vielle's Python 3.12 environment is missing. Run Install-DVielle.bat first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m dvielle
set "DVIELLE_EXIT=%ERRORLEVEL%"
echo D'Vielle exited. Code=%DVIELLE_EXIT%
pause
exit /b %DVIELLE_EXIT%
