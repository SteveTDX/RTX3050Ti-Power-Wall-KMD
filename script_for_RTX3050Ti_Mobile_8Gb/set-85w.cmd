@echo off
title Set GPU power limit to 85W
chcp 65001 >nul

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting administrator privileges via UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    timeout /t 5 >nul
    exit /b
)

rem 60W -> 85W. Best performance per watt; verified 5-minute load.

powershell -NoProfile -ExecutionPolicy Bypass -File "E:\NvwrTools\apply_power.ps1" -Watts 85
echo.
pause
