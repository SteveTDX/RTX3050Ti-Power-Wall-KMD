@echo off
title Deploy rebuilt Nvpwr driver and run read-only probe
chcp 65001 >nul

REM --- self-elevation ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Not elevated - requesting administrator privileges via UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    echo [*] UAC prompt shown.
    timeout /t 5 >nul
    exit /b
)

set DEST=C:\NvpwrCtrl
set BUILD=E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\out\output\dist
set LOG=E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\deploy_probe.log
set SB=E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\probe_new.txt

echo ============================================
echo  Deploy rebuilt driver + read-only probe
echo  log: %LOG%
echo ============================================
> "%LOG%" echo [%date% %time%] === DEPLOY+PROBE START ===

REM --- Defender exclusion first ---
>>"%LOG%" echo === DEFENDER EXCLUSIONS ===
powershell -NoProfile -Command "try { Add-MpPreference -ExclusionPath '%DEST%' -ErrorAction Stop; 'exclusion ok' } catch { 'exclusion: ' + $_.Exception.Message }" >>"%LOG%" 2>&1

REM --- stop and remove old driver service ---
>>"%LOG%" echo === STOP/DELETE OLD SERVICE ===
sc.exe stop Nvpwr >>"%LOG%" 2>&1
sc.exe delete Nvpwr >>"%LOG%" 2>&1
timeout /t 3 /nobreak >nul

REM --- keep a backup of the previously signed driver ---
if exist "%DEST%\Nvpwr.sys" copy /y "%DEST%\Nvpwr.sys" "%TMP%\Nvpwr_prev_signed.sys" >>"%LOG%" 2>&1

REM --- deploy rebuilt driver + CLI ---
>>"%LOG%" echo === DEPLOY REBUILT BINARY ===
copy /y "%BUILD%\Nvpwr.sys" "%DEST%\Nvpwr.sys" >>"%LOG%" 2>&1
copy /y "%BUILD%\NvpwrCtl.exe" "%DEST%\NvpwrCtl.exe" >>"%LOG%" 2>&1
>>"%LOG%" echo --- deployed files ---
dir /b "%DEST%" >>"%LOG%" 2>&1

REM --- sign with the existing test certificate ---
>>"%LOG%" echo === SIGN WITH TEST CERT ===
powershell -NoProfile -ExecutionPolicy Bypass -File "E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\sign_new.ps1" >>"%LOG%" 2>&1

REM --- create + start the kernel service ---
>>"%LOG%" echo === SC CREATE / START ===
sc.exe create Nvpwr type= kernel start= demand binPath= "%DEST%\Nvpwr.sys" >>"%LOG%" 2>&1
sc.exe start Nvpwr >>"%LOG%" 2>&1
sc.exe query Nvpwr >>"%LOG%" 2>&1
sc.exe query Nvpwr | findstr /i "RUNNING" >nul
if errorlevel 1 (
    >>"%LOG%" echo SERVICE NOT RUNNING - probe aborted
    >>"%LOG%" echo === END (LOAD FAILED) ===
    goto :theend
)
>>"%LOG%" echo SERVICE RUNNING

REM --- read-only status probe ---
>>"%LOG%" echo === NvpwrCtl status (READ ONLY) ===
"%DEST%\NvpwrCtl.exe" status > "%SB%" 2>&1
type "%SB%" >>"%LOG%"

>>"%LOG%" echo === GPU STATE (unchanged) ===
nvidia-smi --query-gpu=power.default_limit,power.max_limit,power.draw,temperature.gpu --format=csv >>"%LOG%" 2>&1

>>"%LOG%" echo === END (read-only, nothing written) ===
:theend
echo.
echo DONE. Log: %LOG%
pause
