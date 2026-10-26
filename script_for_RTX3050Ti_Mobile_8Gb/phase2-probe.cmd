@echo off
title Nvpwr Phase 2 Probe (read-only, after reboot)
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
set LOG=%SRC%\phase2_probe.log
set SB=%SRC%\status_before.txt

echo ============================================
echo  Nvpwr Phase 2 Probe - READ ONLY (no power write)
echo  log: %LOG%
echo ============================================
> "%LOG%" echo [%date% %time%] === PHASE2 PROBE START (read-only) ===

>>"%LOG%" echo === TESTSIGNING STATE ===
bcdedit /enum {current} | findstr /i "testsigning" >>"%LOG%" 2>&1

>>"%LOG%" echo === DRIVER SIGNATURE ===
powershell -NoProfile -Command "Get-AuthenticodeSignature '%DEST%\Nvpwr.sys' | Format-List Status,StatusMessage,SignerCertificate" >>"%LOG%" 2>&1

>>"%LOG%" echo === SC RESET / CREATE / START ===
sc.exe stop Nvpwr >>"%LOG%" 2>&1
sc.exe delete Nvpwr >>"%LOG%" 2>&1
sc.exe create Nvpwr type= kernel start= demand binPath= "%DEST%\Nvpwr.sys" >>"%LOG%" 2>&1
sc.exe start Nvpwr >>"%LOG%" 2>&1
sc.exe query Nvpwr >>"%LOG%" 2>&1

set SVC=
sc.exe query Nvpwr | findstr /i "RUNNING" >nul && set "SVC=1"
if not defined SVC (
    >>"%LOG%" echo SERVICE NOT RUNNING - driver load failed, probe aborted
    >>"%LOG%" echo === PROBE COMPLETE (LOAD FAILED) ===
    goto :theend
)
>>"%LOG%" echo SERVICE RUNNING - driver loaded

>>"%LOG%" echo === NVPWRCTL STATUS (read-only GA107 probe) ===
"%DEST%\NvpwrCtl.exe" status > "%SB%" 2>&1
type "%SB%" >>"%LOG%"

set PROBE=
findstr /i /c:"OEM baseline" "%SB%" >nul && set "PROBE=1"
if defined PROBE (
    >>"%LOG%" echo PROBE OK - GA107 power policy objects were resolved
) else (
    >>"%LOG%" echo PROBE FAILED - no OEM baseline line, structures not resolved on this GPU
)

>>"%LOG%" echo === GPU STATE (unchanged) ===
nvidia-smi --query-gpu=power.limit,power.max_limit,power.draw,temperature.gpu,clocks.current.graphics --format=csv >>"%LOG%" 2>&1

>>"%LOG%" echo === PROBE COMPLETE - no power limit was written ===
:theend
echo.
echo ============================================
echo  DONE. Full log: %LOG%
echo ============================================
pause
