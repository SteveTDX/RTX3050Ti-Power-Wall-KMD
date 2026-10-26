@echo off
title Install MSVC C++ Build Tools (VCTools workload)
chcp 65001 >nul

REM --- self-elevation ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Not elevated - requesting administrator privileges via UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    echo [*] UAC prompt shown. The installer window will appear.
    timeout /t 5 >nul
    exit /b
)

set INSTALLER=E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\vs_BuildTools18.exe
set LOGDIR=E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp

echo ============================================
echo  Installing Visual Studio Build Tools
echo  workload: Microsoft.VisualStudio.Workload.VCTools
echo  This downloads ~2-3 GB. Please be patient.
echo ============================================

if not exist "%INSTALLER%" (
    echo [ERROR] Bootstrapper not found: %INSTALLER%
    pause
    exit /b 1
)

"%INSTALLER%" ^
    --quiet ^
    --wait ^
    --norestart ^
    --nocache ^
    --add Microsoft.VisualStudio.Workload.VCTools ^
    --includeRecommended ^
    --installPath "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools"

set RC=%errorlevel%
echo.
echo Installer exit code: %RC%

if exist "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC" (
    echo [OK] VC\Tools\MSVC now exists:
    dir /b "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC"
) else (
    echo [WARN] VC\Tools\MSVC still missing - check installer output above
)

echo.
echo ============================================
echo  DONE. Return to the assistant to continue.
echo ============================================
pause
