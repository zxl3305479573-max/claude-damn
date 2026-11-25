param(
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$installRoot = Join-Path $env:ProgramFiles 'ClaudeDesktopGuardian'
$userState = Join-Path $env:LOCALAPPDATA 'ClaudeDesktopGuardian'
$shortcutPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Claude Desktop Guardian.lnk'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '安装与卸载均需要管理员 PowerShell。'
}

if ($Uninstall) {
    Get-Process -Name 'ClaudeDesktopGuardian.App', 'ClaudeDesktopGuardian.Helper' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 400

    $installedHelper = Join-Path $installRoot 'helper\ClaudeDesktopGuardian.Helper.exe'
    $stateFile = Join-Path $userState 'state.json'
    if (Test-Path -LiteralPath $installedHelper) {
        & $installedHelper --cleanup-all --state-path $stateFile
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "管理员助手清理返回非零退出码：$LASTEXITCODE，将继续移除计划任务与安装文件。"
        }
    }

    Unregister-ScheduledTask -TaskName 'ClaudeDesktopGuardian' -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'ClaudeDesktopGuardian.Helper' -Confirm:$false -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $shortcutPath) {
        Remove-Item -LiteralPath $shortcutPath -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $installRoot) {
        Remove-Item -LiteralPath $installRoot -Recurse -Force
    }
    Write-Host '已清理 WFP 策略、本程序防火墙规则、临时时区、快捷方式与启动任务；用户状态与账号存档保留在：' $userState
    exit 0
}

& (Join-Path $root 'build.ps1')
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
Copy-Item -LiteralPath (Join-Path $root 'publish\win-x64\*') -Destination $installRoot -Recurse -Force
New-Item -ItemType Directory -Force -Path (Join-Path $installRoot 'helper') | Out-Null
Copy-Item -LiteralPath (Join-Path $root 'publish\helper-win-x64\*') -Destination (Join-Path $installRoot 'helper') -Recurse -Force

$app = Join-Path $installRoot 'ClaudeDesktopGuardian.App.exe'
$helper = Join-Path $installRoot 'helper\ClaudeDesktopGuardian.Helper.exe'
$appAction = New-ScheduledTaskAction -Execute $app
$helperAction = New-ScheduledTaskAction -Execute $helper
$trigger = New-ScheduledTaskTrigger -AtLogOn
$taskSettings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'ClaudeDesktopGuardian' -Action $appAction -Trigger $trigger -Settings $taskSettings -Force | Out-Null
Register-ScheduledTask -TaskName 'ClaudeDesktopGuardian.Helper' -Action $helperAction -Trigger $trigger -Settings $taskSettings -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'ClaudeDesktopGuardian.Helper'
Start-ScheduledTask -TaskName 'ClaudeDesktopGuardian'

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $app
$shortcut.WorkingDirectory = $installRoot
$shortcut.IconLocation = "$app,0"
$shortcut.Description = 'Claude Desktop Guardian 网络守护'
$shortcut.Save()

Write-Host '安装完成：Claude Desktop Guardian' -ForegroundColor Green

