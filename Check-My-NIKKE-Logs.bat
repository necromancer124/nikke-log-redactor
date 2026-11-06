@echo off
title NIKKE log check
rem Double-click: finds NIKKE automatically (or asks you for the folder).
rem Drag and drop: drop your debug.log or your NIKKE folder onto this file.
rem Your original logs are only READ, never changed.
if "%~1"=="" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Redact-NikkeLogs.ps1"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Redact-NikkeLogs.ps1" -Path "%~1"
)
echo.
pause
