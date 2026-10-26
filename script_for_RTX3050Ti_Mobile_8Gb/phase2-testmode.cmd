@echo off
title Nvpwr Test Mode Enable and Verify
chcp 65001 >nul

REM --- self-elevation ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Not elevated - requesting administrator privileges via UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    echo [*] UAC prompt shown. If approved, an elevated window will continue.
    timeout /t 5 >nul
    exit /b
)

setlocal
set SRC=E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\nvpwr_run
set LOG=%SRC%\testmode.log

echo ============================================
echo  Test-signing mode: verify and enable
echo  log: %LOG%
echo ============================================
> "%LOG%" echo [%date% %time%] === TESTSIGNING VERIFY/ENABLE ===

>>"%LOG%" echo === CURRENT BOOT ENTRY ===
bcdedit /enum "{current}" >>"%LOG%" 2>&1

findstr /i "testsigning" "%LOG%" | findstr /i "Yes" >nul
if not errorlevel 1 (
    >>"%LOG%" echo RESULT: testsigning already enabled - nothing to do
    goto :theend
)

>>"%LOG%" echo RESULT: testsigning not enabled - enabling now
>>"%LOG%" echo === BCDEDIT /SET TESTSIGNING ON ===
bcdedit /set testsigning on >>"%LOG%" 2>&1

>>"%LOG%" echo === VERIFY AFTER SET ===
bcdedit /enum "{current}" >>"%LOG%" 2>&1

findstr /i "testsigning" "%LOG%" | findstr /i "Yes" >nul
if errorlevel 1 (
    >>"%LOG%" echo FINAL RESULT: STILL NOT ENABLED - do not reboot, report to agent
) else (
    >>"%LOG%" echo FINAL RESULT: testsigning ENABLED - reboot now, then run the probe script
)

:theend
echo.
echo ============================================
echo  DONE. Full log: %LOG%
echo ============================================
pause
