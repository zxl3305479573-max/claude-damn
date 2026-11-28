param(
    [string]$Version = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

if ([string]::IsNullOrWhiteSpace($Version)) {
    $gitTag = $null
    if (Get-Command git -ErrorAction SilentlyContinue) {
        try {
            $gitTag = (& git -C $root describe --tags --match 'guardian-v*' --abbrev=0 2>$null)
            if ($LASTEXITCODE -ne 0) {
                $gitTag = $null
            }
        }
        catch {
            $gitTag = $null
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($gitTag) -and $gitTag.Trim() -match '^guardian-v(\d+\.\d+\.\d+)$') {
        $Version = $Matches[1]
    }
    else {
        $Version = '1.0.5'
    }
}
if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "版本号格式无效：$Version（预期 MAJOR.MINOR.PATCH）"
}

dotnet build (Join-Path $root 'src\ClaudeDesktopGuardian.Core\ClaudeDesktopGuardian.Core.csproj') -c Release "-p:Version=$Version"
if ($LASTEXITCODE -ne 0) {
    throw "核心项目构建失败，退出码 $LASTEXITCODE"
}

dotnet build (Join-Path $root 'src\ClaudeDesktopGuardian.Helper\ClaudeDesktopGuardian.Helper.csproj') -c Release "-p:Version=$Version"
if ($LASTEXITCODE -ne 0) {
    throw "管理员助手构建失败，退出码 $LASTEXITCODE"
}

dotnet build (Join-Path $root 'src\ClaudeDesktopGuardian.App\ClaudeDesktopGuardian.App.csproj') -c Release "-p:Version=$Version"
if ($LASTEXITCODE -ne 0) {
    throw "界面项目构建失败，退出码 $LASTEXITCODE"
}

dotnet build (Join-Path $root 'src\ClaudeDesktopGuardian.Cli\ClaudeDesktopGuardian.Cli.csproj') -c Release "-p:Version=$Version"
if ($LASTEXITCODE -ne 0) {
    throw "命令行项目构建失败，退出码 $LASTEXITCODE"
}

dotnet run --project (Join-Path $root 'tests\ClaudeDesktopGuardian.Tests.csproj') -c Release
if ($LASTEXITCODE -ne 0) {
    throw "核心测试失败，退出码 $LASTEXITCODE"
}

$webrtcJs = Join-Path $root 'src\ClaudeDesktopGuardian.App\web\webrtc\leak-check.js'
if (Get-Command node -ErrorAction SilentlyContinue) {
    node --check $webrtcJs
    if ($LASTEXITCODE -ne 0) {
        throw "WebRTC 脚本语法检查失败，退出码 $LASTEXITCODE"
    }
}

foreach ($psScript in @(
    (Join-Path $root 'build.ps1'),
    (Join-Path $root 'install.ps1'),
    (Join-Path $root 'apply-update.ps1'))) {
    $rawBytes = [System.IO.File]::ReadAllBytes($psScript)
    if ($rawBytes.Length -lt 3 -or $rawBytes[0] -ne 0xEF -or $rawBytes[1] -ne 0xBB -or $rawBytes[2] -ne 0xBF) {
        throw "PowerShell 脚本缺少 UTF-8 BOM：$psScript"
    }
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($psScript, [ref]$null, [ref]$parseErrors)
    if ($parseErrors -and $parseErrors.Count -gt 0) {
        throw "PowerShell 语法错误（$psScript）：$($parseErrors[0].Message)"
    }
}

$publish = Join-Path $root 'publish\win-x64'
$publishRootPrefix = (Join-Path $root 'publish') + '\'
$lockingProcesses = Get-Process -Name 'ClaudeDesktopGuardian.App', 'ClaudeDesktopGuardian.Helper', 'ClaudeDesktopGuardian.Cli' -ErrorAction SilentlyContinue |
    Where-Object {
        $procPath = try { $_.Path } catch { $null }
        -not [string]::IsNullOrWhiteSpace($procPath) -and $procPath.StartsWith($publishRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)
    }
if ($lockingProcesses) {
    $names = $lockingProcesses.ProcessName -join ', '
    throw "请先退出占用 publish 目录的 Guardian 进程后再构建：$names"
}

foreach ($dir in @($publish, (Join-Path $root 'publish\helper-win-x64'), (Join-Path $root 'publish\cli-win-x64'))) {
    if (Test-Path -LiteralPath $dir) {
        Remove-Item -LiteralPath $dir -Recurse -Force
    }
}

# Shared-runtime single-directory publish: Helper + Cli + App share one self-contained .NET 8 runtime
dotnet publish (Join-Path $root 'src\ClaudeDesktopGuardian.Helper\ClaudeDesktopGuardian.Helper.csproj') `
    -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false "-p:Version=$Version" -o $publish
if ($LASTEXITCODE -ne 0) {
    throw "管理员助手发布失败，退出码 $LASTEXITCODE"
}

dotnet publish (Join-Path $root 'src\ClaudeDesktopGuardian.Cli\ClaudeDesktopGuardian.Cli.csproj') `
    -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false "-p:Version=$Version" -o $publish
if ($LASTEXITCODE -ne 0) {
    throw "命令行工具发布失败，退出码 $LASTEXITCODE"
}

dotnet publish (Join-Path $root 'src\ClaudeDesktopGuardian.App\ClaudeDesktopGuardian.App.csproj') `
    -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false "-p:Version=$Version" -o $publish
if ($LASTEXITCODE -ne 0) {
    throw "界面发布失败，退出码 $LASTEXITCODE"
}

Copy-Item -LiteralPath (Join-Path $root 'apply-update.ps1') -Destination $publish
Set-Content -LiteralPath (Join-Path $publish 'VERSION') -Value $Version -Encoding ascii

foreach ($rel in @(
    'ClaudeDesktopGuardian.App.exe',
    'ClaudeDesktopGuardian.Helper.exe',
    'ClaudeDesktopGuardian.Cli.exe',
    'apply-update.ps1',
    'VERSION',
    'Microsoft.Web.WebView2.Wpf.dll',
    'Microsoft.Web.WebView2.Core.dll',
    'WebView2Loader.dll',
    'web\webrtc\index.html',
    'web\webrtc\leak-check.js')) {
    $full = Join-Path $publish $rel
    if (-not (Test-Path -LiteralPath $full)) {
        throw "发布目录缺少必需文件：$rel"
    }
}

$totalBytes = (Get-ChildItem -LiteralPath $publish -Recurse -File | Measure-Object -Property Length -Sum).Sum
$totalMb = [math]::Round($totalBytes / 1MB, 1)
if ($totalMb -ge 195) {
    throw "共享运行时发布目录体积异常偏大：$totalMb MB（预期 < 195 MB）"
}

Write-Host "构建完成：$publish（共享单目录运行时，总体积 $totalMb MB）" -ForegroundColor Green
