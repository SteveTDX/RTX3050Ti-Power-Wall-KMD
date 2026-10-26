@echo off
title Restore GPU to OEM stock 60W
chcp 65001 >nul

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting administrator privileges via UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    timeout /t 5 >nul
    exit /b
)

rem Unloads the custom driver and returns to factory behaviour.

powershell -NoProfile -ExecutionPolicy Bypass -File "E:\NvwrTools\restore_power.ps1"
echo.
pause
