#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackagesRoot,
    [ValidateSet('microsoft.windows.wdk.x64','microsoft.windows.sdk.cpp','microsoft.windows.sdk.cpp.x64')]
    [string[]]$PackageIds = @(
        'microsoft.windows.wdk.x64',
        'microsoft.windows.sdk.cpp',
        'microsoft.windows.sdk.cpp.x64'
    ),
    [ValidatePattern('^10\.0\.26100\.[0-9]{1,10}$')]
    [string]$Version = '10.0.26100.6584'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'

function Get-PackageUrl {
    param([string]$Id, [string]$PackageVersion)
    "https://api.nuget.org/v3-flatcontainer/$Id/$PackageVersion/$Id.$PackageVersion.nupkg"
}

function Test-PackageLayout {
    param([string]$Path, [string]$Id)
    if ($Id -eq 'microsoft.windows.wdk.x64') {
        return (Test-Path -LiteralPath (Join-Path $Path 'c\Include\10.0.26100.0\km\ntddk.h')) -and
            (Test-Path -LiteralPath (Join-Path $Path 'c\Lib\10.0.26100.0\km\x64\ntoskrnl.lib'))
    }
    if ($Id -eq 'microsoft.windows.sdk.cpp') {
        return Test-Path -LiteralPath (Join-Path $Path 'c\Include\10.0.26100.0\um\Windows.h')
    }
    Test-Path -LiteralPath (Join-Path $Path 'c\um\x64\Kernel32.lib')
}

$root = [IO.Path]::GetFullPath($PackagesRoot).TrimEnd('\')
$stageRoot = Join-Path $root ('.staging-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root,$stageRoot -Force | Out-Null

try {
    foreach ($id in $PackageIds) {
        $destination = Join-Path $root "$id\$Version"
        if (Test-PackageLayout -Path $destination -Id $id) {
            Write-Host "依赖已存在：$id $Version"
            continue
        }
        if (Test-Path -LiteralPath $destination) {
            throw "已有依赖目录不完整，请检查后另选缓存目录：$destination"
        }
        $url = Get-PackageUrl -Id $id -PackageVersion $Version
        $uri = [Uri]$url
        if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'api.nuget.org') {
            throw "拒绝非官方 NuGet 地址：$url"
        }
        $archive = Join-Path $stageRoot "$id.$Version.nupkg"
        $extract = Join-Path $stageRoot "$id.$Version"
        Write-Host "下载并展开：$id $Version"
        Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing -TimeoutSec 300
        if (-not (Test-Path -LiteralPath $archive -PathType Leaf) -or
            (Get-Item -LiteralPath $archive).Length -eq 0) {
            throw "NuGet 包下载为空：$id"
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($archive, $extract)
        if (-not (Test-PackageLayout -Path $extract -Id $id)) {
            throw "NuGet 包布局不符合预期：$id $Version"
        }
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Move-Item -LiteralPath $extract -Destination $destination
    }
}
finally {
    if (Test-Path -LiteralPath $stageRoot) {
        $resolved = (Resolve-Path -LiteralPath $stageRoot).ProviderPath
        if (-not $resolved.StartsWith($root + '\.staging-', [StringComparison]::OrdinalIgnoreCase)) {
            throw '临时目录路径越界，拒绝清理。'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

Write-Host '构建依赖已准备完成。'
