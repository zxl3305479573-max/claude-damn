$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

dotnet build (Join-Path $root 'src\ClaudeDesktopGuardian.Core\ClaudeDesktopGuardian.Core.csproj') -c Release
if ($LASTEXITCODE -ne 0) {
    throw "核心项目构建失败，退出码 $LASTEXITCODE"
}

dotnet build (Join-Path $root 'src\ClaudeDesktopGuardian.Helper\ClaudeDesktopGuardian.Helper.csproj') -c Release
if ($LASTEXITCODE -ne 0) {
    throw "管理员助手构建失败，退出码 $LASTEXITCODE"
}

dotnet build (Join-Path $root 'src\ClaudeDesktopGuardian.App\ClaudeDesktopGuardian.App.csproj') -c Release
if ($LASTEXITCODE -ne 0) {
    throw "界面项目构建失败，退出码 $LASTEXITCODE"
}

dotnet build (Join-Path $root 'src\ClaudeDesktopGuardian.Cli\ClaudeDesktopGuardian.Cli.csproj') -c Release
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

foreach ($psScript in @((Join-Path $root 'build.ps1'), (Join-Path $root 'install.ps1'))) {
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
$runningProcesses = Get-Process -Name 'ClaudeDesktopGuardian.App', 'ClaudeDesktopGuardian.Helper' -ErrorAction SilentlyContinue
if ($runningProcesses) {
    $names = $runningProcesses.ProcessName -join ', '
    throw "请先退出 Guardian 后再构建，当前占用发布文件的进程：$names"
}

if (Test-Path -LiteralPath $publish) {
    Remove-Item -LiteralPath $publish -Recurse -Force
}

dotnet publish (Join-Path $root 'src\ClaudeDesktopGuardian.App\ClaudeDesktopGuardian.App.csproj') `
    -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -o $publish
if ($LASTEXITCODE -ne 0) {
    throw "界面发布失败，退出码 $LASTEXITCODE"
}

dotnet publish (Join-Path $root 'src\ClaudeDesktopGuardian.Helper\ClaudeDesktopGuardian.Helper.csproj') `
    -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false `
    -o (Join-Path $root 'publish\helper-win-x64')
if ($LASTEXITCODE -ne 0) {
    throw "管理员助手发布失败，退出码 $LASTEXITCODE"
}

$cliPublish = Join-Path $root 'publish\cli-win-x64'
if (Test-Path -LiteralPath $cliPublish) {
    Remove-Item -LiteralPath $cliPublish -Recurse -Force
}
dotnet publish (Join-Path $root 'src\ClaudeDesktopGuardian.Cli\ClaudeDesktopGuardian.Cli.csproj') `
    -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
    -o $cliPublish
if ($LASTEXITCODE -ne 0) {
    throw "命令行工具发布失败，退出码 $LASTEXITCODE"
}
Copy-Item -LiteralPath (Join-Path $cliPublish 'ClaudeDesktopGuardian.Cli.exe') -Destination (Join-Path $publish 'ClaudeDesktopGuardian.Cli.exe') -Force

Write-Host "构建完成：$publish" -ForegroundColor Green
