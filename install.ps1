param(
    [switch]$Uninstall,
    [switch]$SkipBuild,
    [string]$InstallDir = 'D:\Apps\claude-damn'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$installRoot = $InstallDir.Trim()
if ([string]::IsNullOrWhiteSpace($installRoot)) {
    throw 'InstallDir 不能为空。'
}
$userState = Join-Path $env:LOCALAPPDATA 'ClaudeDesktopGuardian'
$shortcutPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'claude-damn.lnk'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '安装与卸载均需要管理员 PowerShell。'
}

if ($Uninstall) {
    Get-Process -Name 'ClaudeDesktopGuardian.App', 'ClaudeDesktopGuardian.Helper' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 400

    $helperCandidates = @(
        (Join-Path $installRoot 'ClaudeDesktopGuardian.Helper.exe'),
        (Join-Path $installRoot 'helper\ClaudeDesktopGuardian.Helper.exe')
    )
    $installedHelper = $helperCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    $stateFile = Join-Path $userState 'state.json'
    if ($installedHelper) {
        & $installedHelper --cleanup-all --state-path $stateFile
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "管理员助手清理返回非零退出码：$LASTEXITCODE，将继续移除计划任务与安装文件。"
        }
    }

    Unregister-ScheduledTask -TaskName 'ClaudeDesktopGuardian' -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'ClaudeDesktopGuardian.Helper' -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'ClaudeBodyguard' -Confirm:$false -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $shortcutPath) {
        Remove-Item -LiteralPath $shortcutPath -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $installRoot) {
        Remove-Item -LiteralPath $installRoot -Recurse -Force
    }
    Write-Host '已清理 WFP 策略、本程序防火墙规则、临时时区、快捷方式与启动任务；用户状态与账号存档保留在：' $userState
    exit 0
}

$publishDir = Join-Path $root 'publish\win-x64'
if (-not $SkipBuild -or -not (Test-Path -LiteralPath (Join-Path $publishDir 'ClaudeDesktopGuardian.App.exe'))) {
    & (Join-Path $root 'build.ps1')
}

# Stop running Guardian processes cleanly before updating install directory
$existingProcs = Get-Process -Name 'ClaudeDesktopGuardian.App', 'ClaudeDesktopGuardian.Helper', 'ClaudeDesktopGuardian.Cli' -ErrorAction SilentlyContinue
if ($existingProcs) {
    $existingProcs | Stop-Process -Force -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt 25; $i++) {
        Start-Sleep -Milliseconds 200
        if (-not (Get-Process -Name 'ClaudeDesktopGuardian.App', 'ClaudeDesktopGuardian.Helper', 'ClaudeDesktopGuardian.Cli' -ErrorAction SilentlyContinue)) {
            break
        }
    }
}

New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
& robocopy $publishDir $installRoot /MIR /R:3 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) {
    throw "复制安装文件到 $installRoot 失败（robocopy 退出码 $LASTEXITCODE），请确认没有其他程序占用该目录。"
}

$app = Join-Path $installRoot 'ClaudeDesktopGuardian.App.exe'
$helper = Join-Path $installRoot 'ClaudeDesktopGuardian.Helper.exe'
$appAction = New-ScheduledTaskAction -Execute $app
$helperAction = New-ScheduledTaskAction -Execute $helper
$trigger = New-ScheduledTaskTrigger -AtLogOn
$taskSettings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries
Unregister-ScheduledTask -TaskName 'ClaudeBodyguard' -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName 'ClaudeDesktopGuardian' -Action $appAction -Trigger $trigger -Settings $taskSettings -Force | Out-Null
Register-ScheduledTask -TaskName 'ClaudeDesktopGuardian.Helper' -Action $helperAction -Trigger $trigger -Settings $taskSettings -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'ClaudeDesktopGuardian.Helper'
Start-ScheduledTask -TaskName 'ClaudeDesktopGuardian'

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $app
$shortcut.WorkingDirectory = $installRoot
$shortcut.IconLocation = "$app,0"
$shortcut.Description = 'claude-damn 网络守护'
$shortcut.Save()

Write-Host "安装完成：claude-damn（$installRoot）" -ForegroundColor Green

