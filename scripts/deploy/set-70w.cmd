@echo off
title Set GPU power limit to 70W
chcp 65001 >nul

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting administrator privileges via UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    timeout /t 5 >nul
    exit /b
)

rem 60W -> 70W. Small step, coolest running point.

powershell -NoProfile -ExecutionPolicy Bypass -File "E:\NvwrTools\apply_power.ps1" -Watts 70
echo.
pause
