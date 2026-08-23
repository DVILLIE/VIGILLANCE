@echo off
REM Debug launcher — keeps a console so errors are visible.
cd /d C:\DVILLIE
title DVielle - Deep Vigilance (debug)
echo Starting DVielle GUI (console stays open for errors)...
echo.
py -3.12 -m dvielle
echo.
echo DVielle exited. Code=%ERRORLEVEL%
pause
