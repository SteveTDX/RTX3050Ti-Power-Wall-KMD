@echo off
title Install auto-apply at logon (85W)
chcp 65001 >nul

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting administrator privileges via UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    timeout /t 5 >nul
    exit /b
)

rem Registers a scheduled task so 85W is re-applied after every reboot.

powershell -NoProfile -ExecutionPolicy Bypass -File "E:\NvwrTools\install_boottask.ps1"
echo.
pause
