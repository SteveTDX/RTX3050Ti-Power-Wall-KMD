@echo off
title Nvpwr Load Test (idle / load / cooldown sampling)
chcp 65001 >nul

REM --- self-elevation ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Not elevated - requesting administrator privileges via UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    echo [*] UAC prompt shown. A fullscreen animation window will appear for ~45s and close by itself.
    timeout /t 5 >nul
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\nvpwr_run\loadtest.ps1"
echo.
pause
