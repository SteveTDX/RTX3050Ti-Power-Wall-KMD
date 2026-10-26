# restore_power.ps1 - return the GPU to the OEM stock 60W ceiling
param([switch]$RemoveTestMode)
$ErrorActionPreference = 'Continue'

$src  = 'E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp'
$dest = 'C:\NvpwrCtrl'
$exe  = Join-Path $dest 'NvpwrCtl.exe'
$log  = Join-Path $src 'restore_oem.log'

function L($m) { Add-Content -Path $log -Value ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) -Encoding UTF8 }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Set-Content -Path $log -Value ("[{0}] === RESTORE TO OEM 60W (elevated={1}) ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $isAdmin) -Encoding UTF8
L ("elevated: {0}" -f $isAdmin)
if (-not $isAdmin) {
    L 'not elevated -> relaunching with UAC'
    Start-Process powershell.exe -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath) -Verb RunAs
    return
}

$svc = Get-Service Nvpwr -ErrorAction SilentlyContinue
L ("service: {0}" -f $(if ($svc) { $svc.Status } else { 'NOT INSTALLED' }))

if ($svc) {
    L '--- NvpwrCtl restore ---'
    $o = Join-Path $src 'rs_out.txt'
    Remove-Item $o -ErrorAction SilentlyContinue
    $p = Start-Process -FilePath $exe -ArgumentList 'restore' -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError (Join-Path $src 'rs_err.txt')
    if ($p.WaitForExit(30000)) { } else { try { $p.Kill() } catch {}; L '  restore timed out' }
    if (Test-Path $o) { foreach ($line in (Get-Content $o)) { if ($line.Trim()) { L ('  ' + $line.Trim()) } } }

    $o2 = Join-Path $src 'rs_out2.txt'
    Remove-Item $o2 -ErrorAction SilentlyContinue
    $p2 = Start-Process -FilePath $exe -ArgumentList 'status' -NoNewWindow -PassThru -RedirectStandardOutput $o2 -RedirectStandardError (Join-Path $src 'rs_err2.txt')
    if ($p2.WaitForExit(20000)) { } else { try { $p2.Kill() } catch {} }
    L '--- state after restore ---'
    if (Test-Path $o2) { foreach ($line in (Get-Content $o2)) { if ($line -match 'State|OEM baseline|UPPER|Current effective|Applied target') { L ('  ' + $line.Trim()) } } }

    L '--- stopping and removing the driver service ---'
    Stop-Service Nvpwr -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    & sc.exe delete Nvpwr 2>&1 | ForEach-Object { L ('  ' + $_) }
    L 'driver unloaded - the GPU is back to pure stock behaviour'
} else {
    L 'service not present; nothing to restore'
}

$smi = & nvidia-smi --query-gpu=power.default_limit,power.max_limit,power.draw,temperature.gpu --format=csv,noheader 2>&1
L ('  nvidia-smi: ' + ($smi -join ' | '))

if ($RemoveTestMode) {
    L '--- disabling test-signing mode (removes the desktop watermark; requires reboot) ---'
    $b = & bcdedit.exe /set testsigning off 2>&1
    foreach ($m in $b) { L ('  bcdedit: ' + $m) }
    L 'reboot to clear test mode. The custom driver will no longer load afterwards.'
}

L '=== RESTORE COMPLETE ==='
Write-Host ''
Write-Host ('DONE. Log: ' + $log) -ForegroundColor Green
