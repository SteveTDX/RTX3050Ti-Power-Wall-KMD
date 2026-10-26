#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$DriverPath,
    [string]$TargetPath,
    [string]$OutputDirectory,
    [string]$PackagesRoot,
    [string]$Python,
    [string]$DiscoveryReport,
    [ValidateSet('Release', 'Debug')][string]$Configuration = 'Release',
    [switch]$AnalyzeOnly,
    [switch]$NoInstallDependencies
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$encoding = [Console]::OutputEncoding
$previousPythonPath = $env:PYTHONPATH
$previousTls = [Net.ServicePointManager]::SecurityProtocol
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)

function Invoke-ProjectPython {
    param(
        [string]$PythonExe,
        [string[]]$Arguments,
        [switch]$Quiet,
        [ValidateRange(1, 3600)][int]$TimeoutSeconds = 900
    )
    $quoted = foreach ($value in $Arguments) {
        if ($value.IndexOf([char]0) -ge 0 -or $value -match '[\r\n]') {
            throw 'Python 参数包含不允许的控制字符。'
        }
        $escaped = [regex]::Replace($value, '(\\*)"', '$1$1\"')
        $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
        '"' + $escaped + '"'
    }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $PythonExe
    $start.Arguments = $quoted -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw "无法启动 Python：$PythonExe" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            $process.WaitForExit()
            throw "Python 命令超过 $TimeoutSeconds 秒，已停止。"
        }
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr), 30000)) {
            throw 'Python 已退出，但输出流在 30 秒内未关闭。'
        }
        $result = [pscustomobject]@{
            ExitCode = $process.ExitCode
            Stdout = $stdout.GetAwaiter().GetResult()
            Stderr = $stderr.GetAwaiter().GetResult()
        }
        if (-not $Quiet) {
            if ($result.Stdout) { Write-Host $result.Stdout.TrimEnd() }
            if ($result.Stderr) { Write-Host $result.Stderr.TrimEnd() }
        }
        return $result
    }
    finally { $process.Dispose() }
}

function Install-ProjectPython {
    param([string]$RuntimeRoot)
    $version = '3.13.12'
    $stage = Join-Path $RuntimeRoot ('installer-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    $installer = Join-Path $stage "python-$version-amd64.exe"
    $download = $installer + '.download'
    Write-Host "  正在从 Python 官网下载 Python $version x64 完整安装包。" -ForegroundColor Yellow
    $previousProgress = $ProgressPreference
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri "https://www.python.org/ftp/python/$version/python-$version-amd64.exe" `
            -OutFile $download -UseBasicParsing -TimeoutSec 300
    }
    finally { $ProgressPreference = $previousProgress }
    if (-not (Test-Path -LiteralPath $download -PathType Leaf) -or
        (Get-Item -LiteralPath $download).Length -eq 0) {
        throw 'Python 安装包下载为空，未打开安装程序。'
    }
    Move-Item -LiteralPath $download -Destination $installer -ErrorAction Stop
    Write-Host "  安装包：$installer"
    Write-Host '  即将打开安装窗口，请手动安装 Python。' -ForegroundColor Yellow
    $setup = Start-Process -FilePath $installer -WindowStyle Normal -Wait -PassThru
    try {
        $setup.Refresh()
        $setupExitCode = $setup.ExitCode
    }
    finally { $setup.Dispose() }
    if ($setupExitCode -eq 1602) { throw '已取消 Python 安装，本次构建停止；重新运行脚本可再次安装。' }
    if ($setupExitCode -notin @(0, 3010, 1641)) {
        throw "Python 安装程序退出码为 $setupExitCode，本次构建停止。安装包保留在：$installer"
    }
    if ($setupExitCode -in @(3010, 1641)) {
        throw 'Python 安装程序提示需要重启；请按提示重启后重新运行构建脚本。'
    }
    try {
        return (Resolve-BuildPython -Requested '')
    }
    catch {
        throw "安装窗口已关闭，但仍未找到可用的 x64 Python 3.10+。请确认安装已完成；自定义目录可用 -Python 指定 python.exe。`r`n$($_.Exception.Message)"
    }
}

function Install-ProjectCapstone {
    param([string]$PythonExe, [string]$ModuleRoot)
    New-Item -ItemType Directory -Path $ModuleRoot -Force | Out-Null
    $pip = Invoke-ProjectPython -PythonExe $PythonExe `
        -Arguments @('-X', 'utf8', '-B', '-m', 'pip', '--version') -Quiet -TimeoutSeconds 30
    if ($pip.ExitCode -ne 0) {
        # 用户未安装 pip 时，仅将 pip 补充到项目模块目录。
        $bootstrapRoot = Join-Path (Split-Path -Parent $ModuleRoot) 'pip-bootstrap'
        New-Item -ItemType Directory -Path $bootstrapRoot -Force | Out-Null
        $bootstrap = Join-Path $bootstrapRoot 'get-pip.py'
        Write-Host '  当前解释器没有 pip，正在为项目准备 pip。'
        $download = Join-Path $bootstrapRoot ('get-pip-' + [Guid]::NewGuid().ToString('N') + '.py')
        Invoke-WebRequest -Uri 'https://bootstrap.pypa.io/get-pip.py' `
            -OutFile $download -UseBasicParsing -TimeoutSec 180
        if ((Get-Item -LiteralPath $download).Length -eq 0) { throw 'pip 引导脚本下载为空。' }
        Move-Item -LiteralPath $download -Destination $bootstrap -Force
        $installed = Invoke-ProjectPython -PythonExe $PythonExe -Arguments @(
            '-X', 'utf8', '-B', $bootstrap, '--no-setuptools', '--no-wheel', '--no-input',
            '--disable-pip-version-check', '--timeout', '120', '--retries', '5',
            '--no-warn-script-location', '--no-compile', '--no-cache-dir', '--target', $ModuleRoot
        )
        if ($installed.ExitCode -ne 0) { throw '项目内 pip 安装失败，具体原因见上方 pip 输出。' }
        $pip = Invoke-ProjectPython -PythonExe $PythonExe `
            -Arguments @('-X', 'utf8', '-B', '-m', 'pip', '--version')
        if ($pip.ExitCode -ne 0) {
            throw 'pip 已准备但当前解释器无法加载，请检查项目模块搜索路径。'
        }
    }
    Write-Host '  使用当前 Python 的 pip 安装 Capstone 5.0.6 到项目目录。'
    $installed = Invoke-ProjectPython -PythonExe $PythonExe -Arguments @(
        '-X', 'utf8', '-B', '-m', 'pip', 'install', '--disable-pip-version-check', '--no-input',
        '--timeout', '120', '--retries', '5', '--only-binary=:all:', '--no-deps', '--upgrade',
        '--no-warn-script-location', '--no-compile', '--no-cache-dir', '--target', $ModuleRoot, 'capstone==5.0.6'
    )
    if ($installed.ExitCode -ne 0) {
        throw 'pip 安装 Capstone 失败；请根据上方输出检查网络、代理或 pip 源配置。'
    }
}

function Resolve-BuildPython {
    param([string]$Requested)
    $candidates = New-Object 'System.Collections.Generic.List[object]'
    $failures = New-Object 'System.Collections.Generic.List[string]'
    if ($Requested) {
        $expanded = [Environment]::ExpandEnvironmentVariables($Requested.Trim('"'))
        if (Test-Path -LiteralPath $expanded -PathType Container) {
            $expanded = Join-Path $expanded 'python.exe'
        }
        $command = Get-Command -Name $expanded -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $command) { throw "指定的 Python 程序不存在：$Requested（请传 exe 路径，不要附加参数）" }
        $candidates.Add([pscustomobject]@{ Path = $command.Source; Prefix = '' })
    }
    else {
        foreach ($name in @('python.exe', 'python3.exe', 'py.exe')) {
            foreach ($command in @(Get-Command $name -All -CommandType Application -ErrorAction SilentlyContinue)) {
                # python 的 WindowsApps 别名可能打开商店；交给 py 启动器定位实际解释器。
                if ($name -ne 'py.exe' -and $command.Source -like '*\WindowsApps\*') { continue }
                $prefix = if ($name -eq 'py.exe') { '-3 ' } else { '' }
                $candidates.Add([pscustomobject]@{ Path = $command.Source; Prefix = $prefix })
            }
        }
        foreach ($base in @('HKCU:\Software\Python', 'HKLM:\Software\Python',
            'HKLM:\Software\WOW6432Node\Python')) {
            foreach ($provider in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
                foreach ($runtime in @(Get-ChildItem -LiteralPath $provider.PSPath -ErrorAction SilentlyContinue)) {
                    $install = Join-Path $runtime.PSPath 'InstallPath'
                    $key = Get-Item -LiteralPath $install -ErrorAction SilentlyContinue
                    if (-not $key) { continue }
                    foreach ($path in @($key.GetValue('ExecutablePath'),
                        $(if ($key.GetValue('')) { Join-Path ([string]$key.GetValue('')) 'python.exe' }))) {
                        if ($path) { $candidates.Add([pscustomobject]@{ Path = [string]$path; Prefix = '' }) }
                    }
                }
            }
        }
        foreach ($parent in @(
            $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Programs\Python' }),
            $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Python' }),
            $env:ProgramFiles
        )) {
            if (-not $parent) { continue }
            foreach ($directory in @(Get-ChildItem -LiteralPath $parent -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like 'Python*' })) {
                $candidates.Add([pscustomobject]@{ Path = (Join-Path $directory.FullName 'python.exe'); Prefix = '' })
            }
        }
        foreach ($launcher in @(
            $(if ($env:WINDIR) { Join-Path $env:WINDIR 'py.exe' }),
            $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Programs\Python\Launcher\py.exe' }),
            $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\py.exe' })
        )) {
            if ($launcher) { $candidates.Add([pscustomobject]@{ Path = $launcher; Prefix = '-3 ' }) }
        }
    }
    $seen = @{}
    # 探测放在子进程，避免修改 PATH；返回实际解释器，而不是继续依赖启动器。
    $probe = 'import sys,json,struct,platform; print(json.dumps(dict(executable=sys.executable,version=list(sys.version_info[:3]),bits=struct.calcsize(''P'')*8,machine=platform.machine())))'
    foreach ($candidate in $candidates) {
        $path = $candidate.Path
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or $seen.ContainsKey($path)) { continue }
        $seen[$path] = $true
        $process = New-Object Diagnostics.Process
        $start = New-Object Diagnostics.ProcessStartInfo
        $start.FileName = $path
        $start.Arguments = $candidate.Prefix + '-I -X utf8 -c "' + $probe + '"'
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $process.StartInfo = $start
        try {
            if (-not $process.Start()) { throw '进程无法启动' }
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(15000)) {
                $process.Kill()
                $process.WaitForExit()
                throw '解释器探测超过 15 秒'
            }
            $output = $stdout.GetAwaiter().GetResult()
            $errorText = $stderr.GetAwaiter().GetResult()
            if ($process.ExitCode -ne 0) { throw "退出码 $($process.ExitCode)：$errorText" }
            $info = $output.Trim() | ConvertFrom-Json
            if ($info.version.Count -lt 2 -or
                ($info.version[0] -lt 3 -or ($info.version[0] -eq 3 -and $info.version[1] -lt 10))) {
                throw '解释器版本低于 3.10'
            }
            if ($info.bits -ne 64 -or $info.machine -notmatch '^(AMD64|x86_64)$') {
                throw '需要 x64 Python，当前解释器架构不匹配'
            }
            if (-not (Test-Path -LiteralPath $info.executable -PathType Leaf)) {
                throw '实际解释器路径无效'
            }
            Write-Host ('  Python版本：{0}（64 位）' -f ($info.version -join '.'))
            return [string]$info.executable
        }
        catch { $failures.Add("$path：$($_.Exception.Message)") }
        finally { $process.Dispose() }
    }
    $details = $failures -join [Environment]::NewLine
    throw "未找到可用的 x64 Python 3.10+。已尝试 PATH、py 启动器、注册表及常见安装目录。`r`n" +
        "可在已打开的 Python 窗口输入 import sys; print(sys.executable)，再用 -Python 指定该路径。`r`n$details"
}

try {
    Write-Host ''
    Write-Host '========== 构建任务 ==========' -ForegroundColor Cyan
    Write-Host ('  模式     : {0}' -f $(if ($AnalyzeOnly) { '仅分析' } else { '构建' }))
    Write-Host ('  配置     : {0}' -f $Configuration)
    Write-Host ''
    Write-Host '[1] 检查运行环境' -ForegroundColor Cyan
    if (-not $PackagesRoot) { $PackagesRoot = Join-Path $PSScriptRoot 'dependencies\packages' }
    $PackagesRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PackagesRoot)
    $pythonPackages = Join-Path $PackagesRoot 'python'
    $runtimeRoot = Join-Path $PackagesRoot 'runtime'
    [Net.ServicePointManager]::SecurityProtocol = $previousTls -bor [Net.SecurityProtocolType]::Tls12
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {
        throw '请使用 Windows x64 的 64 位 PowerShell。'
    }
    $requestedPython = $Python
    try {
        $Python = Resolve-BuildPython -Requested $requestedPython
    }
    catch {
        if ($requestedPython -or $NoInstallDependencies) { throw }
        Write-Host "  未发现可用解释器：$($_.Exception.Message)" -ForegroundColor Yellow
        $Python = Install-ProjectPython -RuntimeRoot $runtimeRoot
    }
    $env:PYTHONPATH = (@($pythonPackages, $previousPythonPath) | Where-Object { $_ }) -join ';'
    $capstoneCheck = Join-Path $PSScriptRoot 'tools\check-capstone.py'
    if (-not (Test-Path -LiteralPath $capstoneCheck -PathType Leaf)) {
        throw "缺少依赖检查脚本：$capstoneCheck"
    }
    $check = Invoke-ProjectPython -PythonExe $Python `
        -Arguments @('-X', 'utf8', '-B', $capstoneCheck, '--quiet') -Quiet -TimeoutSeconds 30
    if ($check.ExitCode -ne 0) {
        if ($NoInstallDependencies) { throw '缺少 capstone 反汇编依赖；离线模式不下载。' }
        Install-ProjectCapstone -PythonExe $Python -ModuleRoot $pythonPackages
        $check = Invoke-ProjectPython -PythonExe $Python `
            -Arguments @('-X', 'utf8', '-B', $capstoneCheck) -TimeoutSeconds 30
        if ($check.ExitCode -ne 0) { throw '项目内 Capstone 准备后仍不可用，具体原因见上方依赖检查信息。' }
    }
    Write-Host ('  Python   : {0}' -f $Python)
    Write-Host ''
    Write-Host '[2] 定位驱动与目标配置' -ForegroundColor Cyan

    if (-not $DriverPath) {
        $drivers = @(Get-CimInstance Win32_SystemDriver -Filter "Name='nvlddmkm'")
        if ($drivers.Count -ne 1) { throw '无法定位唯一驱动，请指定 -DriverPath。' }
        $DriverPath = [Environment]::ExpandEnvironmentVariables(([string]$drivers[0].PathName).Trim('"'))
        if ($DriverPath.StartsWith('\??\')) { $DriverPath = $DriverPath.Substring(4) }
        if ($DriverPath.StartsWith('\\?\')) { $DriverPath = $DriverPath.Substring(4) }
        if ($DriverPath.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
            $DriverPath = Join-Path $env:SystemRoot $DriverPath.Substring(12)
        }
        elseif ($DriverPath.StartsWith('System32\', [StringComparison]::OrdinalIgnoreCase)) {
            $DriverPath = Join-Path $env:SystemRoot $DriverPath
        }
    }
    $DriverPath = (Resolve-Path -LiteralPath $DriverPath).ProviderPath
    if ($TargetPath) { $TargetPath = (Resolve-Path -LiteralPath $TargetPath).ProviderPath }
    if (-not (Test-Path -LiteralPath $DriverPath -PathType Leaf)) { throw '驱动路径不是文件。' }
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($DriverPath).FileVersion
    Write-Host ('  驱动     : {0}' -f $DriverPath)
    Write-Host ('  版本     : {0}' -f $version)
    Write-Host ('  目标配置 : {0}' -f $(if ($TargetPath) { $TargetPath } else { '自动从当前映像发现' }))
    $arguments = @('-X', 'utf8', '-B', (Join-Path $PSScriptRoot 'tools\adapt.py'),
        '--image', $DriverPath, '--version', $version)
    if ($TargetPath) { $arguments += @('--target', $TargetPath) }
    $analysisReport = $DiscoveryReport

    if (-not $AnalyzeOnly) {
        if (-not $OutputDirectory) {
            $name = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([Guid]::NewGuid().ToString('N').Substring(0, 8))
            $OutputDirectory = Join-Path $PSScriptRoot "build\$name"
        }
        $OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
        if (Test-Path -LiteralPath $OutputDirectory) { throw '输出目录必须不存在，拒绝覆盖。' }
        Write-Host ('  构建目录 : {0}' -f $OutputDirectory)
        $source = Join-Path $OutputDirectory 'source'
        New-Item -ItemType Directory -Path "$source\src\driver","$source\src\cli","$source\src\shared" -Force | Out-Null
        $arguments += @('--header', (Join-Path $source 'src\driver\nvpwr_target.h'))
        if (-not $analysisReport) { $analysisReport = Join-Path $OutputDirectory 'analysis.json' }
    }
    if ($analysisReport) { $arguments += @('--diagnostics', $analysisReport) }

    Write-Host ''
    Write-Host '[3] 分析驱动并检查目标' -ForegroundColor Cyan
    $analysis = Invoke-ProjectPython -PythonExe $Python -Arguments $arguments -TimeoutSeconds 900
    if ($analysis.ExitCode -ne 0) {
        if ($analysisReport) { Write-Host "  诊断路径 : $analysisReport（若写入失败，上方会另行提示）" }
        throw "目标检查失败，退出码 $($analysis.ExitCode)。"
    }
    if ($analysisReport) {
        if (-not $DiscoveryReport -and
            (-not (Test-Path -LiteralPath $analysisReport -PathType Leaf) -or
                (Get-Item -LiteralPath $analysisReport).Length -eq 0)) {
            throw "默认分析报告未能写入或内容为空：$analysisReport"
        }
        Write-Host "  诊断路径 : $analysisReport"
    }
    if (-not $AnalyzeOnly) {
        Write-Host ''
        Write-Host '[4] 准备源码并编译' -ForegroundColor Cyan
        Write-Host ('  依赖目录 : {0}' -f $PackagesRoot)
        Write-Host ('  缺失依赖 : {0}' -f $(if ($NoInstallDependencies) { '不自动安装' } else { '允许自动安装' }))
        foreach ($relative in @('driver\driver.c','cli\nvpwrctl.cpp','shared\nvpwr_ioctl.h')) {
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot "src\$relative") -Destination (Join-Path $source "src\$relative")
        }
        $output = Join-Path $OutputDirectory 'output'
        New-Item -ItemType Directory -Path $output | Out-Null
        $engine = (Get-Process -Id $PID).Path
        $compile = @('-NoProfile', '-NonInteractive', '-File',
            (Join-Path $PSScriptRoot 'tools\compile.ps1'), '-SourceRoot', $source,
            '-OutputRoot', $output, '-Configuration', $Configuration, '-PackagesRoot', $PackagesRoot)
        if (-not $NoInstallDependencies) { $compile += '-InstallMissingDependencies' }
        & $engine @compile
        if ($LASTEXITCODE -ne 0) { throw "编译失败，退出码 $LASTEXITCODE。" }
        Write-Host ''
        Write-Host '========== 构建成功 ==========' -ForegroundColor Green
        Write-Host "  产物目录 : $output\dist" -ForegroundColor Green
        Write-Host '  验证范围 : 离线分析与未签名编译；未验证驱动加载、功耗写入或回滚。' -ForegroundColor Yellow
    }
    else {
        Write-Host ''
        Write-Host '========== 分析完成 ==========' -ForegroundColor Green
    }
}
catch {
    Write-Host ''
    Write-Host '========== 任务失败 ==========' -ForegroundColor Red
    Write-Host "  原因：$($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    [Console]::OutputEncoding = $encoding
    $env:PYTHONPATH = $previousPythonPath
    [Net.ServicePointManager]::SecurityProtocol = $previousTls
}
