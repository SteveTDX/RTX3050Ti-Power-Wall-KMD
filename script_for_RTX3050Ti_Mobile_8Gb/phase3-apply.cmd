@echo off
title Nvpwr Phase 3 Apply 75W
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
set DEST=C:\NvpwrCtrl
set LOG=%SRC%\phase3_apply.log

echo ============================================
echo  Nvpwr Phase 3 - apply 75W (60 -> 75 step)
echo  log: %LOG%
echo ============================================
> "%LOG%" echo [%date% %time%] === PHASE3 APPLY 75W START ===

>>"%LOG%" echo === SERVICE STATE ===
sc.exe query Nvpwr >>"%LOG%" 2>&1
sc.exe query Nvpwr | findstr /i "RUNNING" >nul
if errorlevel 1 (
    >>"%LOG%" echo SERVICE NOT RUNNING - aborting, no power limit was written
    >>"%LOG%" echo === APPLY ABORTED ===
    goto :theend
)
>>"%LOG%" echo SERVICE RUNNING - proceeding

>>"%LOG%" echo === STATUS BEFORE ===
"%DEST%\NvpwrCtl.exe" status > "%SRC%\p3_before.txt" 2>&1
type "%SRC%\p3_before.txt" >>"%LOG%"

findstr /i /c:"OEM baseline" "%SRC%\p3_before.txt" >nul
if errorlevel 1 (
    >>"%LOG%" echo OEM BASELINE NOT RESOLVED - aborting before any write
    >>"%LOG%" echo === APPLY ABORTED ===
    goto :theend
)

>>"%LOG%" echo === SET UNLIMITED 75W ===
"%DEST%\NvpwrCtl.exe" set unlimited 75 > "%SRC%\p3_set.txt" 2>&1
type "%SRC%\p3_set.txt" >>"%LOG%"

>>"%LOG%" echo === STATUS AFTER ===
"%DEST%\NvpwrCtl.exe" status > "%SRC%\p3_after.txt" 2>&1
type "%SRC%\p3_after.txt" >>"%LOG%"

>>"%LOG%" echo === GPU STATE AFTER SET ===
nvidia-smi --query-gpu=power.limit,power.max_limit,power.draw,temperature.gpu,clocks.current.graphics --format=csv >>"%LOG%" 2>&1

>>"%LOG%" echo === ROLLBACK COMMAND (if needed) ===
>>"%LOG%" echo C:\NvpwrCtrl\NvpwrCtl.exe restore

>>"%LOG%" echo === APPLY COMPLETE ===
:theend
echo.
echo ============================================
echo  DONE. Full log: %LOG%
echo ============================================
pause
