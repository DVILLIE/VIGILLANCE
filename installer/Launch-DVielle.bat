@echo off
REM Silent GUI launch — no leftover console window.
cd /d C:\DVILLIE

where py >nul 2>&1
if %errorLevel%==0 (
  start "" py -3.12w -m dvielle
  exit /b 0
)

REM Fallback: pythonw beside python.exe
for /f "delims=" %%I in ('py -3.12 -c "import sys; print(sys.executable)" 2^>nul') do set "PYEXE=%%I"
if defined PYEXE (
  set "PYW=%PYEXE:python.exe=pythonw.exe%"
  if exist "%PYW%" (
    start "" "%PYW%" -m dvielle
    exit /b 0
  )
  start "" "%PYEXE%" -m dvielle
  exit /b 0
)

echo Could not find Python 3.12. Install from https://python.org
pause
