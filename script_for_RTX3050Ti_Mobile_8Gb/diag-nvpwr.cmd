@echo off
title Nvpwr Phase1 Diagnostic v3 (no DSE write)
chcp 65001 >nul

REM --- self-elevation ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Not elevated - requesting administrator privileges via UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    timeout /t 5 >nul
    exit /b
)

setlocal
set SRC=E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp\nvpwr_run
set DEST=C:\NvpwrCtrl
set LOG=%SRC%\phase1_diag.log

echo ============================================
echo  Nvpwr Diagnostic v3 - READ ONLY, no DSE write
echo  log: %LOG%
echo ============================================
> "%LOG%" echo [%date% %time%] === DIAG v3 START ===

>>"%LOG%" echo === 1. COPY MINIDUMP FOR ANALYSIS ===
if exist "C:\Windows\Minidump\*.dmp" (
    copy /y "C:\Windows\Minidump\*.dmp" "%SRC%\" >>"%LOG%" 2>&1
) else (
    echo no minidump found >>"%LOG%" 2>&1
)
dir /b "%SRC%\*.dmp" >>"%LOG%" 2>&1

>>"%LOG%" echo === 2. KDU PROVIDER LIST (read-only) ===
cd /d "%DEST%"
KDU.exe -list >>"%LOG%" 2>&1

>>"%LOG%" echo === 3. NVPWR SERVICE STATE ===
sc.exe query Nvpwr >>"%LOG%" 2>&1

>>"%LOG%" echo === 4. GPU STATE AFTER REBOOT ===
nvidia-smi --query-gpu=name,power.draw,power.max_limit,power.default_limit,temperature.gpu --format=csv >>"%LOG%" 2>&1

>>"%LOG%" echo === 5. LOG SELF-CHECK ===
for %A in ("%LOG%") do @echo log size: %~zA bytes >>"%LOG%" 2>&1

>>"%LOG%" echo === DIAG v3 COMPLETE ===
echo.
echo ============================================
echo  DONE (diagnostic only - no DSE write).
echo  Log: %LOG%
echo ============================================
pause
