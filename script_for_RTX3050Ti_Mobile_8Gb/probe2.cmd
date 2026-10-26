@echo off
title Nvpwr Probe2 (PowerShell)
chcp 65001 >nul

REM --- self-elevation (verified working pattern from phase1/phase2 scripts) ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Not elevated - requesting administrator privileges via UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    echo [*] UAC prompt shown. If approved, an elevated window will continue.
    timeout /t 5 >nul
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\nvpwr_run\probe2.ps1"
echo.
pause
