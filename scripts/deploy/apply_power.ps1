# apply_power.ps1 - one-shot: restore to OEM baseline, then apply the requested power target
# Self-elevates. Logs to its own file (never shares a log with a cmd redirect).
param(
    [Parameter(Mandatory=$true)][ValidateSet('70','85','90')][string]$Watts
)
$ErrorActionPreference = 'Continue'

$src  = 'E:\workbuddy\3050nvpwrcontrol\.workbuddy\tmp'
$dest = 'C:\NvpwrCtrl'
$exe  = Join-Path $dest 'NvpwrCtl.exe'
$log  = Join-Path $src ("apply{0}.log" -f $Watts)

function L($m) { Add-Content -Path $log -Value ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) -Encoding UTF8 }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Set-Content -Path $log -Value ("[{0}] === APPLY {1}W (elevated={2}) ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Watts, $isAdmin) -Encoding UTF8
L ("elevated: {0}" -f $isAdmin)
if (-not $isAdmin) {
    L 'not elevated -> relaunching with UAC'
    Start-Process powershell.exe -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Watts {1}' -f $PSCommandPath, $Watts) -Verb RunAs
    return
}

function Run-Ctl([string]$argline, [string]$tag, [int]$timeoutMs = 30000) {
    $o = Join-Path $src 'ap_out.txt'; $e = Join-Path $src 'ap_err.txt'
    Remove-Item $o, $e -ErrorAction SilentlyContinue
    L ("--- NvpwrCtl {0} [{1}] ---" -f $argline, $tag)
    $p = Start-Process -FilePath $exe -ArgumentList $argline -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
    if (-not $p.WaitForExit($timeoutMs)) { try { $p.Kill() } catch {}; L '  TIMED OUT'; return @{ text=''; code=-1 } }
    $txt=''; if (Test-Path $o) { $txt = Get-Content $o -Raw }
    $etxt=''; if (Test-Path $e) { $etxt = Get-Content $e -Raw }
    $all = $txt + "`n" + $etxt
    foreach ($line in ($all -split "`r?`n")) { if ($line.Trim()) { L ('  ' + $line.Trim()) } }
    return @{ text=$all; code=$p.ExitCode }
}

# ---- ensure the kernel driver service exists and runs ----
$svc = Get-Service Nvpwr -ErrorAction SilentlyContinue
if (-not $svc) {
    L 'service missing -> creating'
    & sc.exe create Nvpwr type= kernel start= demand binPath= "$dest\Nvpwr.sys" 2>&1 | ForEach-Object { L ('  ' + $_) }
    Start-Sleep -Seconds 2
    $svc = Get-Service Nvpwr -ErrorAction SilentlyContinue
}
if ($svc -and $svc.Status -ne 'Running') {
    L 'service stopped -> starting'
    & sc.exe start Nvpwr 2>&1 | ForEach-Object { L ('  ' + $_) }
    Start-Sleep -Seconds 2
    $svc = Get-Service Nvpwr -ErrorAction SilentlyContinue
}
L ("service: {0}" -f $(if ($svc) { $svc.Status } else { 'MISSING' }))
if (-not $svc -or $svc.Status -ne 'Running') { L 'ABORT: driver service not running'; exit 1 }

# ---- STEP 1: restore to the OEM baseline (required: the driver cannot re-apply) ----
L '=== STEP 1: restore to OEM baseline ==='
$r = Run-Ctl 'restore' 'restore'
$st = Run-Ctl 'status' 'check'
if ($st.text -notmatch 'STOCK_BASELINE') {
    L 'ABORT: not at STOCK_BASELINE after restore'
    exit 2
}
L 'baseline confirmed'

# ---- STEP 2: apply the target from the stock baseline ----
L ("=== STEP 2: apply {0}W ===" -f $Watts)
$set = Run-Ctl ("set unlimited " + $Watts) 'set'
Start-Sleep -Seconds 2
$after = Run-Ctl 'status' 'after'

L '=== VERDICT ==='
$tw = [int]$Watts * 1000
if ($after.text -match ('Applied target\s*:\s*' + $tw)) {
    L (">>> SUCCESS: {0}W applied" -f $Watts)
    $smi = & nvidia-smi --query-gpu=power.default_limit,power.max_limit,power.draw,temperature.gpu --format=csv,noheader 2>&1
    L ('  nvidia-smi: ' + ($smi -join ' | '))
    exit 0
} else {
    L ('>>> FAILED - rolled back to OEM 60W (target was {0}W)' -f $Watts)
    $smi = & nvidia-smi --query-gpu=power.default_limit,power.max_limit,power.draw,temperature.gpu --format=csv,noheader 2>&1
    L ('  nvidia-smi: ' + ($smi -join ' | '))
    exit 3
}
