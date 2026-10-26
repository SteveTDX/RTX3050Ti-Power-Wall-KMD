@echo off
title Nvpwr Phase 2 Prep v1 (route0 probe + test-signing)
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
set LOG=%SRC%\phase2_prep.log

echo ============================================
echo  Nvpwr Phase 2 Prep
echo  log: %LOG%
echo ============================================
> "%LOG%" echo [%date% %time%] === PHASE2 PREP START ===

REM --- STEP 0: Defender exclusions (before touching any tool file) ---
>>"%LOG%" echo === DEFENDER EXCLUSIONS ===
powershell -NoProfile -Command "foreach ($p in @('%DEST%','%SRC%')) { try { Add-MpPreference -ExclusionPath $p -ErrorAction Stop; 'exclusion ok: ' + $p } catch { 'exclusion: ' + $p + ' -> ' + $_.Exception.Message } }" >>"%LOG%" 2>&1

REM --- STEP 1: stage driver + user-mode CLI (no KDU needed on this route) ---
if not exist "%DEST%" mkdir "%DEST%"
>>"%LOG%" echo === STAGE DRIVER + CLI ===
copy /y "%SRC%\Nvpwr.sys" "%DEST%\" >>"%LOG%" 2>&1
copy /y "%SRC%\NvpwrCtl.exe" "%DEST%\" >>"%LOG%" 2>&1
dir /b "%DEST%" >>"%LOG%" 2>&1

REM --- STEP 2: archive the 09:47 BSOD dump for the record ---
>>"%LOG%" echo === COPY LATEST MINIDUMP ===
copy /y "C:\Windows\Minidump\101626-42625-01.dmp" "%SRC%\" >>"%LOG%" 2>&1

REM --- STEP 3: ROUTE 0 probe - can plain NVAPI set the limit when elevated? (zero risk) ---
>>"%LOG%" echo === ROUTE 0 PROBE: nvidia-smi -pl 85 ===
set PLB=
for /f "tokens=1 delims=," %%p in ('nvidia-smi --query-gpu=power.limit --format=csv,noheader,nounits 2^>^&1') do set "PLB=%%p"
>>"%LOG%" echo power.limit before          : [%PLB%]
nvidia-smi -pl 85 >>"%LOG%" 2>&1
set PLA=
for /f "tokens=1 delims=," %%p in ('nvidia-smi --query-gpu=power.limit --format=csv,noheader,nounits 2^>^&1') do set "PLA=%%p"
>>"%LOG%" echo power.limit after -pl 85    : [%PLA%]
echo %PLA%| findstr /r /c:"^85" >nul && set "ROUTE0=1"
if defined ROUTE0 (
    >>"%LOG%" echo ROUTE0_WORKS - NVAPI power limit API is functional on this GPU
    >>"%LOG%" echo restoring 60W baseline
    nvidia-smi -pl 60 >>"%LOG%" 2>&1
    >>"%LOG%" echo === PREP COMPLETE - ROUTE 0: no driver, no reboot needed ===
    goto :theend
)

REM --- STEP 4: ROUTE C - test-sign the driver so it loads with DSE untouched ---
>>"%LOG%" echo === ROUTE C: TEST-SIGN DRIVER ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%SRC%\prep_testsign.ps1" >>"%LOG%" 2>&1

>>"%LOG%" echo === PREP COMPLETE ===
:theend
echo.
echo ============================================
echo  DONE. Full log: %LOG%
echo ============================================
pause
