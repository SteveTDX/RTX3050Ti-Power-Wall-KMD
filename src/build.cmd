@echo off
setlocal
where pwsh.exe >nul 2>nul
if errorlevel 1 (
    powershell.exe -NoLogo -NoProfile -File "%~dp0build.ps1" %*
) else (
    pwsh.exe -NoLogo -NoProfile -File "%~dp0build.ps1" %*
)
set "result=%errorlevel%"
echo.
echo Exit code: %result%
if "%~1"=="" pause
exit /b %result%
