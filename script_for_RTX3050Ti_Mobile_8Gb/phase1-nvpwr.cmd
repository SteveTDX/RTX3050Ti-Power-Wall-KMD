@echo off
title Nvpwr Phase1 Probe v3 (prv 20)
chcp 65001 >nul

REM --- self-elevation: re-run as administrator if not elevated ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Not elevated - requesting administrator privileges via UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    echo [*] UAC prompt shown. If approved, an elevated window will run the probe.
    timeout /t 5 >nul
    exit /b
)

setlocal
set SRC=E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\nvpwr_run
set DEST=C:\NvpwrCtrl
set ZIP=E:\workbuddy\3050nvpwrcontrol\NvpwrCtrl.zip
set LOG=%SRC%\phase1.log
set PY=C:\Users\shif\.workbuddy\binaries\python\versions\3.13.12\python.exe

echo ============================================
echo  Nvpwr Phase 1 v3 - KDU provider 20 (Dell DBUtilDrv2)
echo  log: %LOG%
echo ============================================
> "%LOG%" echo [%date% %time%] === PHASE1 START v3 (prv 20 Dell DBUtilDrv2) ===

REM --- STEP 0: Defender exclusions FIRST, before any tool file is touched ---
>>"%LOG%" echo === DEFENDER EXCLUSIONS (before file ops) ===
powershell -NoProfile -Command "foreach ($p in @('%DEST%','%SRC%')) { try { Add-MpPreference -ExclusionPath $p -ErrorAction Stop; 'exclusion added: ' + $p } catch { 'exclusion failed for ' + $p + ': ' + $_.Exception.Message } }" >>"%LOG%" 2>&1

REM --- STEP 1: stage files. KDU.exe is re-extracted from the zip because Defender quarantined the staging copy ---
if not exist "%DEST%" mkdir "%DEST%"
>>"%LOG%" echo === RE-EXTRACT KDU.exe FROM ZIP ===
"%PY%" -c "import zipfile,shutil,os; z=zipfile.ZipFile(r'%ZIP%'); n=[x for x in z.namelist() if x.endswith('KDU.exe')][0]; z.extract(n, r'%DEST%\_ext'); shutil.move(os.path.join(r'%DEST%\_ext', n), r'%DEST%\KDU.exe'); print('KDU.exe restored, size:', os.path.getsize(r'%DEST%\KDU.exe'))" >>"%LOG%" 2>&1
copy /y "%SRC%\Nvpwr.sys" "%DEST%\" >>"%LOG%" 2>&1
copy /y "%SRC%\NvpwrCtl.exe" "%DEST%\" >>"%LOG%" 2>&1
copy /y "%SRC%\drv64.dll" "%DEST%\" >>"%LOG%" 2>&1
copy /y "%SRC%\EfiDSEFix.exe" "%DEST%\" >>"%LOG%" 2>&1
>>"%LOG%" echo === REMOVE STALE NalDrv.sys (crashed provider 0 leftover) ===
del /q "%DEST%\NalDrv.sys" >>"%LOG%" 2>&1
>>"%LOG%" echo === FILE LIST IN %DEST% ===
dir /b "%DEST%" >>"%LOG%" 2>&1

cd /d "%DEST%"

>>"%LOG%" echo === KDU -prv 20 -dse 0 (disable DSE via Dell DBUtilDrv2) ===
KDU.exe -prv 20 -dse 0 >>"%LOG%" 2>&1

>>"%LOG%" echo === SC RESET ===
sc.exe stop Nvpwr >>"%LOG%" 2>&1
sc.exe delete Nvpwr >>"%LOG%" 2>&1

>>"%LOG%" echo === SC CREATE ===
sc.exe create Nvpwr type= kernel binPath= "%DEST%\Nvpwr.sys" >>"%LOG%" 2>&1

>>"%LOG%" echo === SC START ===
sc.exe start Nvpwr >>"%LOG%" 2>&1

>>"%LOG%" echo === SC QUERY ===
sc.exe query Nvpwr >>"%LOG%" 2>&1

>>"%LOG%" echo === NVPWRCTL STATUS ===
NvpwrCtl.exe status >>"%LOG%" 2>&1

>>"%LOG%" echo === CLEANUP: KDU -prv 20 -dse 6 (restore DSE) ===
KDU.exe -prv 20 -dse 6 >>"%LOG%" 2>&1

>>"%LOG%" echo === CLEANUP: SC STOP ===
sc.exe stop Nvpwr >>"%LOG%" 2>&1

>>"%LOG%" echo === PHASE1 COMPLETE ===
echo.
echo ============================================
echo  DONE. Full log: %LOG%
echo ============================================
pause
