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

dotnet run --project (Join-Path $root 'tests\ClaudeDesktopGuardian.Tests.csproj') -c Release
if ($LASTEXITCODE -ne 0) {
    throw "核心测试失败，退出码 $LASTEXITCODE"
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

Write-Host "构建完成：$publish" -ForegroundColor Green
