@echo off
title Set GPU power limit to 90W
chcp 65001 >nul

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting administrator privileges via UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    timeout /t 5 >nul
    exit /b
)

rem 60W -> 90W. Hardware ceiling; gains over 85W are marginal.

powershell -NoProfile -ExecutionPolicy Bypass -File "E:\NvwrTools\apply_power.ps1" -Watts 90
echo.
pause
