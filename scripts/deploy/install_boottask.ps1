# install_boottask.ps1 - create a logon-triggered scheduled task that applies 85W every boot
$ErrorActionPreference = 'Continue'

$src     = 'E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp'
$dest    = 'C:\NvpwrCtrl'
$log     = Join-Path $src 'boot_task.log'
$taskName = 'NvpwrApply85W'
$runner  = Join-Path $dest 'run_apply85w.cmd'
$applyScript = 'E:\NvwrTools\apply_power.ps1'

function L($m) { Add-Content -Path $log -Value ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) -Encoding UTF8 }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Set-Content -Path $log -Value ("[{0}] === INSTALL BOOT TASK (elevated={1}) ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $isAdmin) -Encoding UTF8
L ("elevated: {0}" -f $isAdmin)
if (-not $isAdmin) {
    L 'not elevated -> relaunching with UAC'
    Start-Process powershell.exe -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath) -Verb RunAs
    return
}

# ---- 1. the runner batch that the task will call ----
$runnerBody = @(
    '@echo off',
    'title Nvpwr auto-apply 85W',
    ('powershell -NoProfile -ExecutionPolicy Bypass -File "' + $applyScript + '" -Watts 85'),
    'exit /b %errorlevel%'
) -join "`r`n"
$runnerBody = $runnerBody + "`r`n"
Set-Content -LiteralPath $runner -Value $runnerBody -Encoding ASCII -NoNewline
L ("runner written: {0}" -f $runner)

# ---- 2. register the scheduled task ----
L ("registering task '{0}' (logon trigger, highest privileges)" -f $taskName)
& schtasks.exe /Delete /TN $taskName /F 2>&1 | ForEach-Object { L ('  ' + $_) }

$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$action  = New-ScheduledTaskAction -Execute $runner
$principal = New-ScheduledTaskPrincipal -UserId ('{0}\{1}' -f $env:COMPUTERNAME, $env:USERNAME) `
                -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -StartWhenAvailable

try {
    Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action `
        -Principal $principal -Settings $settings -Force | Out-Null
    L 'task registered OK'
} catch {
    L ("Register-ScheduledTask failed: {0}" -f $_.Exception.Message)
    L 'falling back to schtasks.exe'
    $cmd = 'schtasks.exe /Create /TN "{0}" /SC ONLOGON /TR "{1}" /RL HIGHEST /F' -f $taskName, $runner
    & schtasks.exe /Create /TN $taskName /SC ONLOGON /TR $runner /RL HIGHEST /F 2>&1 | ForEach-Object { L ('  ' + $_) }
}

L '--- task list ---'
& schtasks.exe /Query /TN $taskName /V /FO LIST 2>&1 | ForEach-Object { L ('  ' + $_) }

L '--- running it once now to verify ---'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $applyScript -Watts 85 2>&1 |
    ForEach-Object { $_ -split "`r?`n" } | Where-Object { $_ } | ForEach-Object { L ('  ' + $_) }

$smi = & nvidia-smi --query-gpu=power.default_limit,power.max_limit,power.draw,temperature.gpu --format=csv,noheader 2>&1
L ('  nvidia-smi: ' + ($smi -join ' | '))
L '=== BOOT TASK INSTALL COMPLETE ==='
Write-Host ''
Write-Host ('DONE. Log: ' + $log) -ForegroundColor Green
