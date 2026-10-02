@echo off
setlocal
cd /d "%~dp0.."
if not exist ".venv\Scripts\DVielle.exe" (
  if not exist ".venv\Scripts\pythonw.exe" (
    echo DVielle's Python 3.12 environment is missing. Run Install-DVielle.bat first.
    pause
    exit /b 1
  )
  echo Building the branded DVielle.exe console host...
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\scripts\New-DvielleGuiExe.ps1" -InstallDir "%cd%"
  if errorlevel 1 (
    echo Could not build DVielle.exe. Re-run Install-DVielle.bat.
    pause
    exit /b 1
  )
)
start "" ".venv\Scripts\DVielle.exe" -m dvielle
exit /b %errorlevel%
