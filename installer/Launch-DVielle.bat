@echo off
setlocal
cd /d "%~dp0.."
if not exist ".venv\Scripts\pythonw.exe" (
  echo DVielle's Python 3.12 environment is missing. Run Install-DVielle.bat first.
  pause
  exit /b 1
)
start "" ".venv\Scripts\pythonw.exe" -m dvielle
exit /b %errorlevel%
