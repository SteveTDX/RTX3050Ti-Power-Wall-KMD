[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceRoot,
    [Parameter(Mandatory)][string]$OutputRoot,
    [ValidateSet('Release', 'Debug')][string]$Configuration = 'Release',
    [string]$PackagesRoot,
    [switch]$InstallMissingDependencies
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
$script:Utf8 = New-Object System.Text.UTF8Encoding($false)
$script:BuildLog = $null
$runLock = $null
$exitCode = 1

function Write-BuildLog {
    param([string]$Message)
    $line = '{0} {1}' -f [DateTime]::UtcNow.ToString('o'), $Message
    if ($script:BuildLog) {
        [System.IO.File]::AppendAllText($script:BuildLog, $line + [Environment]::NewLine, $script:Utf8)
    }
    Write-Host $line
}

function Assert-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "缺少文件：$Path"
    }
    if ((Get-Item -LiteralPath $Path).Length -eq 0) {
        throw "文件为空：$Path"
    }
}

function Get-DirectoryPath {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or $item.PSProvider.Name -ne 'FileSystem') {
        throw "必须是已存在的文件系统目录：$Path"
    }
    return $item.FullName.TrimEnd([char[]]'\/')
}

function Test-Within {
    param([string]$Path, [string]$Parent)
    return $Path.Equals($Parent, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($Parent + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Assert-NoReparsePoint {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "输出目录及其祖先不能包含重解析点：$($item.FullName)"
        }
        $item = $item.Parent
    }
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string]$Value)
    if ($Value.IndexOf([char]0) -ge 0 -or $Value -match '[\r\n]') {
        throw '本机命令参数含不允许的控制字符。'
    }
    # 按 Windows argv 规则转义，避开不同 PowerShell 版本的参数重组。
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Invoke-Native {
    param(
        [string]$Name,
        [string]$Executable,
        [string[]]$Arguments,
        [string[]]$ExpectedFiles = @(),
        [string]$BinDirectory = '',
        [switch]$Utf8Output
    )
    Assert-File $Executable
    $stdoutPath = Join-Path $script:Logs ($Name + '.stdout.log')
    $stderrPath = Join-Path $script:Logs ($Name + '.stderr.log')
    $argumentLine = ($Arguments | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' '
    Write-BuildLog "执行 $Name：$Executable $argumentLine"
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.Arguments = $argumentLine
    $info.WorkingDirectory = $script:Work
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    if ($Utf8Output) {
        $info.StandardOutputEncoding = $script:Utf8
        $info.StandardErrorEncoding = $script:Utf8
    }
    foreach ($variable in @('CL', '_CL_', 'LINK', '_LINK_', 'INCLUDE', 'LIB', 'LIBPATH')) {
        $info.EnvironmentVariables.Remove($variable)
    }
    if ($BinDirectory) {
        $info.EnvironmentVariables['PATH'] = $BinDirectory + ';' + $env:PATH
    }
    $info.EnvironmentVariables['TEMP'] = $script:Temp
    $info.EnvironmentVariables['TMP'] = $script:Temp
    $info.EnvironmentVariables['VSLANG'] = '1033'
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw "无法启动：$Executable" }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(600000)) {
            $process.Kill()
            $process.WaitForExit()
            throw "$Name 超过十分钟等待上限，已停止本次构建进程。"
        }
        $nativeExitCode = $process.ExitCode
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        [IO.File]::WriteAllText($stdoutPath, $stdout, $script:Utf8)
        [IO.File]::WriteAllText($stderrPath, $stderr, $script:Utf8)
        Write-BuildLog "$Name 退出码：$nativeExitCode"
        if ($nativeExitCode -ne 0) {
            throw "$Name 失败，退出码 $nativeExitCode；详见 $stdoutPath 和 $stderrPath"
        }
        foreach ($file in $ExpectedFiles) { Assert-File $file }
        return $stdout
    }
    finally {
        $process.Dispose()
    }
}

function Get-VersionDirectories {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    Get-ChildItem -LiteralPath $Path -Directory |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+(\.\d+)?$' } |
        Sort-Object @{ Expression = { [version]$_.Name }; Descending = $true }
}

function Find-Msvc {
    $roots = New-Object 'System.Collections.Generic.List[string]'
    $programRoots = @(${env:ProgramFiles(x86)}, $env:ProgramFiles) |
        Where-Object { $_ } | Select-Object -Unique
    $discoveryNumber = 0
    foreach ($programRoot in $programRoots) {
        $vswhere = Join-Path $programRoot 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
            $discoveryNumber++
            $text = Invoke-Native -Name "vswhere-$discoveryNumber" -Executable $vswhere -Utf8Output -Arguments @(
                '-all', '-products', '*', '-requires',
                'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath', '-utf8'
            )
            foreach ($line in ($text -split '\r?\n')) {
                if ($line.Trim()) { $roots.Add($line.Trim()) }
            }
        }
    }
    foreach ($programRoot in $programRoots) {
        foreach ($generation in @('18', '2026', '2022', '2019', '2017')) {
            foreach ($edition in @('BuildTools', 'Enterprise', 'Professional', 'Community', 'Preview')) {
                $roots.Add((Join-Path $programRoot "Microsoft Visual Studio\$generation\$edition"))
            }
        }
    }
    $candidates = @(
        foreach ($root in ($roots | Select-Object -Unique)) {
            foreach ($versionDir in @(Get-VersionDirectories (Join-Path $root 'VC\Tools\MSVC'))) {
                $msvc = $versionDir.FullName
                $bin = Join-Path $msvc 'bin\Hostx64\x64'
                $runtimeSuffix = if ($Configuration -eq 'Debug') { 'd' } else { '' }
                $required = @(
                    'bin\Hostx64\x64\cl.exe', 'bin\Hostx64\x64\link.exe',
                    'include\vcruntime.h', 'include\cstdio', 'include\cwchar',
                    "lib\x64\libcmt$runtimeSuffix.lib",
                    "lib\x64\libcpmt$runtimeSuffix.lib",
                    "lib\x64\libvcruntime$runtimeSuffix.lib"
                )
                $missing = @($required | Where-Object {
                    -not (Test-Path -LiteralPath (Join-Path $msvc $_) -PathType Leaf)
                })
                if ($missing.Count -eq 0) {
                    [pscustomobject]@{
                        vsRoot = $root
                        root = $msvc
                        version = $versionDir.Name
                        bin = $bin
                        cl = Join-Path $bin 'cl.exe'
                        link = Join-Path $bin 'link.exe'
                        include = Join-Path $msvc 'include'
                        lib = Join-Path $msvc 'lib\x64'
                    }
                }
                else {
                    Write-BuildLog "跳过不完整 MSVC $msvc；缺少：$($missing -join ', ')"
                }
            }
        }
    )
    if ($candidates.Count -eq 0) {
        throw '未发现完整的 MSVC Hostx64/x64 编译器、链接器、头文件和对应配置运行库。'
    }
    return $candidates | Sort-Object @{ Expression = { [version]$_.version }; Descending = $true } |
        Select-Object -First 1
}

function New-KitCandidate {
    param(
        [string]$Kind, [string]$Version, [string]$KmInclude, [string]$SdkInclude,
        [string]$KmLib, [string]$UmLib, [string]$UcrtLib, [string[]]$Roots
    )
    $candidate = [pscustomobject]@{
        kind = $Kind
        version = $Version
        roots = @($Roots)
        kmInclude = $KmInclude
        kmCrtInclude = Join-Path $KmInclude 'crt'
        sharedInclude = Join-Path $SdkInclude 'shared'
        umInclude = Join-Path $SdkInclude 'um'
        ucrtInclude = Join-Path $SdkInclude 'ucrt'
        kmLib = $KmLib
        umLib = $UmLib
        ucrtLib = $UcrtLib
        bin = Join-Path (Split-Path -Parent (Split-Path -Parent $SdkInclude)) "bin\$Version\x64"
    }
    # NuGet 的头文件包不一定包含构建工具；只复用同一 kit 版本的已安装工具。
    $binCandidates = @(
        $candidate.bin,
        $(if ($env:WindowsSdkDir) { Join-Path $env:WindowsSdkDir "bin\$Version\x64" }),
        $(if (${env:ProgramFiles(x86)}) {
            Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin\$Version\x64"
        }),
        $(if ($env:ProgramFiles) {
            Join-Path $env:ProgramFiles "Windows Kits\10\bin\$Version\x64"
        })
    ) | Where-Object { $_ } | Select-Object -Unique
    foreach ($bin in $binCandidates) {
        $missingTools = @('rc.exe', 'rcdll.dll', 'mt.exe') | Where-Object {
            -not (Test-Path -LiteralPath (Join-Path $bin $_) -PathType Leaf)
        }
        if (@($missingTools).Count -eq 0) {
            $candidate.bin = $bin
            break
        }
    }
    $ucrtName = if ($Configuration -eq 'Debug') { 'libucrtd.lib' } else { 'libucrt.lib' }
    $required = @(
        (Join-Path $candidate.bin 'rc.exe'),
        (Join-Path $candidate.bin 'rcdll.dll'),
        (Join-Path $candidate.bin 'mt.exe'),
        (Join-Path $candidate.kmInclude 'ntddk.h'),
        (Join-Path $candidate.kmInclude 'ntimage.h'),
        (Join-Path $candidate.kmInclude 'aux_klib.h'),
        (Join-Path $candidate.kmCrtInclude 'stddef.h'),
        (Join-Path $candidate.sharedInclude 'sdkddkver.h'),
        (Join-Path $candidate.sharedInclude 'ntdef.h'),
        (Join-Path $candidate.umInclude 'Windows.h'),
        (Join-Path $candidate.umInclude 'winioctl.h'),
        (Join-Path $candidate.ucrtInclude 'corecrt.h'),
        (Join-Path $candidate.ucrtInclude 'stdio.h'),
        (Join-Path $candidate.umLib 'Advapi32.lib'),
        (Join-Path $candidate.umLib 'Kernel32.lib'),
        (Join-Path $candidate.ucrtLib $ucrtName)
    )
    foreach ($library in @('Aux_Klib.lib', 'BufferOverflowFastFailK.lib', 'ntoskrnl.lib', 'hal.lib', 'wmilib.lib')) {
        $required += Join-Path $candidate.kmLib $library
    }
    $missing = @($required | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) })
    if ($missing.Count -gt 0) {
        Write-BuildLog "跳过不完整 $Kind $Version；缺少：$($missing -join ', ')"
        return
    }
    return $candidate
}

function Find-Kit {
    $kitRoots = @(
        $env:WindowsSdkDir, $env:WDKContentRoot,
        $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10' }),
        $(if ($env:ProgramFiles) { Join-Path $env:ProgramFiles 'Windows Kits\10' })
    ) | Where-Object { $_ } | Select-Object -Unique
    $installed = @(
        foreach ($kit in $kitRoots) {
            foreach ($versionDir in @(Get-VersionDirectories (Join-Path $kit 'Include'))) {
                $v = $versionDir.Name
                New-KitCandidate -Kind 'installed' -Version $v -KmInclude (Join-Path $versionDir.FullName 'km') `
                    -SdkInclude $versionDir.FullName -KmLib (Join-Path $kit "Lib\$v\km\x64") `
                    -UmLib (Join-Path $kit "Lib\$v\um\x64") -UcrtLib (Join-Path $kit "Lib\$v\ucrt\x64") `
                    -Roots @($kit)
            }
        }
    )
    if ($installed.Count -gt 0) {
        return $installed | Sort-Object @{ Expression = { [version]$_.version }; Descending = $true } |
            Select-Object -First 1
    }
    $cacheRoots = @(
        $PackagesRoot,
        $env:NUGET_PACKAGES,
        $(if ($env:USERPROFILE) { Join-Path $env:USERPROFILE '.nuget\packages' })
    ) | Where-Object { $_ } | Select-Object -Unique
    $cached = @(
        foreach ($cache in $cacheRoots) {
            $wdkPackages = @(Get-VersionDirectories (Join-Path $cache 'microsoft.windows.wdk.x64'))
            $sdkPackages = @(Get-VersionDirectories (Join-Path $cache 'microsoft.windows.sdk.cpp'))
            foreach ($wdk in $wdkPackages) {
                foreach ($includeVersion in @(Get-VersionDirectories (Join-Path $wdk.FullName 'c\Include'))) {
                    $v = $includeVersion.Name
                    foreach ($sdk in $sdkPackages) {
                        # SDK 头和 x64 库必须属于同一个 NuGet 包版本，内部 kit 版本必须与 WDK 相同。
                        $sdkX64 = Join-Path $cache "microsoft.windows.sdk.cpp.x64\$($sdk.Name)"
                        $sdkInclude = Join-Path $sdk.FullName "c\Include\$v"
                        if (-not (Test-Path -LiteralPath $sdkInclude -PathType Container) -or
                            -not (Test-Path -LiteralPath $sdkX64 -PathType Container)) { continue }
                        $umLib = Join-Path $sdkX64 'c\um\x64'
                        $ucrtLib = Join-Path $sdkX64 'c\ucrt\x64'
                        if (Test-Path -LiteralPath (Join-Path $sdkX64 "c\Lib\$v\um\x64") -PathType Container) {
                            $umLib = Join-Path $sdkX64 "c\Lib\$v\um\x64"
                            $ucrtLib = Join-Path $sdkX64 "c\Lib\$v\ucrt\x64"
                        }
                        New-KitCandidate -Kind 'nuget-cache' -Version $v `
                            -KmInclude (Join-Path $includeVersion.FullName 'km') -SdkInclude $sdkInclude `
                            -KmLib (Join-Path $wdk.FullName "c\Lib\$v\km\x64") -UmLib $umLib -UcrtLib $ucrtLib `
                            -Roots @($wdk.FullName, $sdk.FullName, $sdkX64)
                    }
                }
            }
        }
    )
    if ($cached.Count -eq 0) {
        return $null
    }
    return $cached | Sort-Object @{ Expression = { [version]$_.version }; Descending = $true } |
        Select-Object -First 1
}

try {
    $source = Get-DirectoryPath $SourceRoot
    $output = Get-DirectoryPath $OutputRoot
    Assert-NoReparsePoint $output
    if ((Test-Within $output $source) -or (Test-Within $source $output)) {
        throw 'SourceRoot 与 OutputRoot 必须互相独立，不能相同或互为父子目录。'
    }
    if (@(Get-ChildItem -LiteralPath $output -Force).Count -ne 0) {
        throw "OutputRoot 必须是已创建的全新空目录，拒绝覆盖已有 run：$output"
    }
    # CreateNew 和独占句柄共同阻止两个构建认领同一 run；失败后保留现场，不自动清理。
    $lockPath = Join-Path $output '.compile.lock'
    $runLock = [IO.File]::Open($lockPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    if (@(Get-ChildItem -LiteralPath $output -Force | Where-Object { $_.Name -ne '.compile.lock' }).Count -ne 0) {
        throw '认领输出目录期间出现其他文件，停止构建。'
    }
    $script:BuildLog = Join-Path $output 'build.log'
    $script:Work = Join-Path $output 'obj'
    $script:Logs = Join-Path $output 'logs'
    $script:Temp = Join-Path $output 'temp'
    $dist = Join-Path $output 'dist'
    foreach ($directory in @($script:Work, $script:Logs, $script:Temp, $dist)) {
        [void][IO.Directory]::CreateDirectory($directory)
    }
    Write-BuildLog "开始仅未签名构建；配置：$Configuration；源码：$source；输出：$output"
    $driverSource = Join-Path $source 'src\driver\driver.c'
    $cliSource = Join-Path $source 'src\cli\nvpwrctl.cpp'
    $sharedHeader = Join-Path $source 'src\shared\nvpwr_ioctl.h'
    $targetHeader = Join-Path $source 'src\driver\nvpwr_target.h'
    $sourcePaths = @($driverSource, $cliSource, $sharedHeader, $targetHeader)
    foreach ($path in $sourcePaths) { Assert-File $path }
    $headerText = [IO.File]::ReadAllText($targetHeader)
    if ($headerText -match 'NVPWR_MANUAL_BOARD_SET_RVA_REQUIRED') {
        throw '目标头仍含人工复核错误保护，拒绝构建。'
    }
    $msvc = Find-Msvc
    $kit = Find-Kit
    if (-not $kit) {
        if (-not $InstallMissingDependencies) {
            throw '未发现完整且版本匹配的 x64 SDK/WDK；本次禁用了自动安装依赖。'
        }
        if (-not $PackagesRoot) { throw '安装依赖时必须提供项目内 PackagesRoot。' }
        $installer = Join-Path $PSScriptRoot 'ensure-dependencies.ps1'
        Assert-File $installer
        Write-BuildLog "缺少 SDK/WDK，安装官方 NuGet 构建依赖到：$PackagesRoot"
        $engine = (Get-Process -Id $PID).Path
        $null = Invoke-Native -Name 'install-dependencies' -Executable $engine -Utf8Output -Arguments @(
            '-NoProfile', '-NonInteractive', '-File', $installer, '-PackagesRoot', $PackagesRoot
        )
        $kit = Find-Kit
        if (-not $kit) { throw '依赖安装完成后仍未发现完整匹配的 SDK/WDK，请检查安装日志。' }
    }
    Write-BuildLog "选择 MSVC $($msvc.version)：$($msvc.bin)"
    Write-BuildLog "选择 SDK/WDK $($kit.version)：$($kit.kind)"
    $nativePath = $msvc.bin + ';' + $kit.bin

    $driverObj = Join-Path $script:Work 'driver.obj'
    $driverCompilerPdb = Join-Path $script:Work 'driver-compiler.pdb'
    $driverSys = Join-Path $script:Work 'Nvpwr.sys'
    $driverPdb = Join-Path $script:Work 'Nvpwr.pdb'
    $cliObj = Join-Path $script:Work 'nvpwrctl.obj'
    $cliCompilerPdb = Join-Path $script:Work 'cli-compiler.pdb'
    $cliExe = Join-Path $script:Work 'NvpwrCtl.exe'
    $cliPdb = Join-Path $script:Work 'NvpwrCtl.pdb'
    $sharedInclude = Join-Path $source 'src\shared'
    $driverArgs = @(
        '/c', '/nologo', '/W4', '/utf-8', '/Zi', '/kernel',
        '/D_WIN64', '/D_AMD64_', '/DAMD64', '/D_WIN32_WINNT=0x0A00',
        '/DWINVER=0x0A00', '/DWINNT=1', '/DNTDDI_VERSION=0xA000012',
        '/I', $kit.kmInclude, '/I', $kit.kmCrtInclude, '/I', $kit.sharedInclude,
        '/I', $kit.ucrtInclude, '/I', $msvc.include, '/I', $sharedInclude,
        "/Fo$driverObj", "/Fd$driverCompilerPdb"
    )
    $cliArgs = @(
        '/c', '/nologo', '/W4', '/std:c++17', '/utf-8', '/EHsc', '/Zi',
        '/I', $kit.umInclude, '/I', $kit.sharedInclude, '/I', $kit.ucrtInclude,
        '/I', $msvc.include, '/I', $sharedInclude, "/Fo$cliObj", "/Fd$cliCompilerPdb"
    )
    $optimization = @('/OPT:REF', '/OPT:ICF')
    if ($Configuration -eq 'Debug') {
        $driverArgs += @('/Od', '/DDBG=1', '/D_DEBUG')
        $cliArgs += @('/Od', '/MTd', '/D_DEBUG')
        $optimization = @('/OPT:NOREF', '/OPT:NOICF')
    }
    else {
        $driverArgs += @('/Ox', '/DDBG=0', '/DNDEBUG')
        $cliArgs += @('/O2', '/MT', '/DNDEBUG')
    }
    $driverArgs += $driverSource
    $cliArgs += $cliSource
    $driverLinkArgs = @('/nologo', '/WX', '/SECTION:INIT,d')
    foreach ($library in @('Aux_Klib.lib', 'BufferOverflowFastFailK.lib', 'ntoskrnl.lib', 'hal.lib', 'wmilib.lib')) {
        $driverLinkArgs += Join-Path $kit.kmLib $library
    }
    $driverLinkArgs += @(
        '/NODEFAULTLIB', '/MANIFEST:NO', '/DEBUG:FULL', '/INCREMENTAL:NO',
        '/SUBSYSTEM:NATIVE,10.00', '/Driver', '/ENTRY:GsDriverEntry', '/RELEASE',
        '/MERGE:_TEXT=.text;_PAGE=PAGE', '/MACHINE:X64', '/kernel',
        "/OUT:$driverSys", "/PDB:$driverPdb", $driverObj
    ) + $optimization
    $cliLinkArgs = @(
        '/nologo', '/SUBSYSTEM:CONSOLE', '/MACHINE:X64', '/RELEASE',
        '/DEBUG:FULL', '/INCREMENTAL:NO', '/MANIFEST:EMBED',
        "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'",
        "/LIBPATH:$($msvc.lib)", "/LIBPATH:$($kit.umLib)", "/LIBPATH:$($kit.ucrtLib)",
        'Advapi32.lib', 'Kernel32.lib', "/OUT:$cliExe", "/PDB:$cliPdb", $cliObj
    ) + $optimization
    $null = Invoke-Native -Name 'driver-compile' -Executable $msvc.cl -Arguments $driverArgs `
        -ExpectedFiles @($driverObj, $driverCompilerPdb) -BinDirectory $nativePath
    $null = Invoke-Native -Name 'driver-link' -Executable $msvc.link -Arguments $driverLinkArgs `
        -ExpectedFiles @($driverSys, $driverPdb) -BinDirectory $nativePath
    $null = Invoke-Native -Name 'cli-compile' -Executable $msvc.cl -Arguments $cliArgs `
        -ExpectedFiles @($cliObj, $cliCompilerPdb) -BinDirectory $nativePath
    $null = Invoke-Native -Name 'cli-link' -Executable $msvc.link -Arguments $cliLinkArgs `
        -ExpectedFiles @($cliExe, $cliPdb) -BinDirectory $nativePath

    foreach ($builtPath in @($driverSys, $cliExe)) {
        $destination = Join-Path $dist ([IO.Path]::GetFileName($builtPath))
        [IO.File]::Copy($builtPath, $destination, $false)
        Assert-File $destination
    }
    Write-BuildLog "构建完成：$dist"
    $exitCode = 0
}
catch {
    $failure = $_.Exception.Message
    try { Write-BuildLog "构建失败：$failure" }
    catch { [Console]::Error.WriteLine('构建日志写入失败：' + $_.Exception.Message) }
    [Console]::Error.WriteLine($failure)
}
finally {
    if ($null -ne $runLock) { $runLock.Dispose() }
}
exit $exitCode
