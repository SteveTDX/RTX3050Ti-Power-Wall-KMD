@echo off
title Build Nvpwr driver for GA107 (RTX 3050 Ti Laptop)
chcp 65001 >nul

set HTTP_PROXY=http://127.0.0.1:7890
set HTTPS_PROXY=http://127.0.0.1:7890

set SRC=E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\src
set LOG=E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\build.log
set PKGS=E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\deps\packages
set PY=C:\Users\shif\.workbuddy\binaries\python\envs\default\Scripts\python.exe

echo ============================================
echo  Nvpwr build for GA107
echo  source   : %SRC%
echo  packages : %PKGS%
echo ============================================

cd /d "%SRC%"

powershell -NoProfile -ExecutionPolicy Bypass -File "%SRC%\build.ps1" ^
    -Python "%PY%" ^
    -PackagesRoot "%PKGS%" ^
    -NoInstallDependencies ^
    -OutputDirectory "E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\out"

echo.
echo build exit code: %errorlevel%

echo === output ===
dir /s /b "E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\out"

echo DONE. Log: %LOG%
pause
