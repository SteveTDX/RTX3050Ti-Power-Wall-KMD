@echo off
title Add VCTools workload to existing VS Build Tools
chcp 65001 >nul

REM --- self-elevation ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Not elevated - requesting administrator privileges via UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    echo [*] UAC prompt shown. An installer window may appear.
    timeout /t 5 >nul
    exit /b
)

set SETUP="C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe"
set INSTALLPATH=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools

echo ============================================
echo  Adding VCTools to existing Build Tools 18
echo  installPath: %INSTALLPATH%
echo  This downloads ~1.5-2.5 GB. Please wait.
echo ============================================

if not exist %SETUP% (
    echo [ERROR] VS Installer setup.exe not found
    pause
    exit /b 1
)

%SETUP% modify ^
    --installPath "%INSTALLPATH%" ^
    --quiet ^
    --norestart ^
    --nocache ^
    --add Microsoft.VisualStudio.Workload.VCTools ^
    --includeRecommended

set RC=%errorlevel%
echo.
echo Installer exit code: %RC%

REM --- wait for the background installer to finish, then verify ---
echo Waiting for installer to finish (checking every 15s)...
:waitloop
set DONE=0
for /f "tokens=2" %%p in ('tasklist /fi "imagename eq setup.exe" /nh 2^>nul ^| findstr /i "setup.exe"') do set DONE=1
timeout /t 15 /nobreak >nul
tasklist /fi "imagename eq setup.exe" 2>nul | findstr /i "setup.exe" >nul || goto :verify
goto :waitloop

:verify
set VCDIR=%INSTALLPATH%\VC\Tools\MSVC
if exist "%VCDIR%" (
    echo [OK] VC\Tools\MSVC installed:
    dir /b "%VCDIR%"
) else (
    echo [WARN] VC\Tools\MSVC still missing
    echo        Check %%TEMP%%\dd_*.log for details.
)

echo.
echo ============================================
echo  DONE. Return to the assistant to continue.
echo ============================================
pause
