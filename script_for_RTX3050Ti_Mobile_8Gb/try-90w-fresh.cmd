@echo off
title Restore then apply 90W from stock baseline, then verify
chcp 65001 >nul

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    timeout /t 5 >nul
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\try90_fresh.ps1"
echo.
pause
