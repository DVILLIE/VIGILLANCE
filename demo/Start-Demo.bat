@echo off
cd /d "%~dp0"
where node >nul 2>&1
if errorlevel 1 (
  echo Node.js is required. Install from https://nodejs.org then re-run this.
  pause
  exit /b 1
)
if not exist node_modules (
  echo Installing demo packages...
  call npm install
)
echo.
echo Starting DVielle Demo at http://127.0.0.1:43123
echo Keep this window open. Press Ctrl+C to stop.
echo.
call npm run dev -- --host 127.0.0.1 --port 43123
pause
