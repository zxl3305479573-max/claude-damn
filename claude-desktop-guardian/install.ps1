param(
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$installRoot = Join-Path $env:ProgramFiles 'ClaudeDesktopGuardian'
$userState = Join-Path $env:LOCALAPPDATA 'ClaudeDesktopGuardian'

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName 'ClaudeDesktopGuardian' -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'ClaudeDesktopGuardian.Helper' -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $installRoot) {
        Remove-Item -LiteralPath $installRoot -Recurse -Force
    }
    Write-Host '已移除程序和启动任务，用户状态保留在：' $userState
    exit 0
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '安装需要管理员 PowerShell。'
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
Register-ScheduledTask -TaskName 'ClaudeDesktopGuardian' -Action $appAction -Trigger $trigger -Force | Out-Null
Register-ScheduledTask -TaskName 'ClaudeDesktopGuardian.Helper' -Action $helperAction -Trigger $trigger -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'ClaudeDesktopGuardian.Helper'
Start-ScheduledTask -TaskName 'ClaudeDesktopGuardian'

$shell = New-Object -ComObject WScript.Shell
$shortcutPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Claude Desktop Guardian.lnk'
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $app
$shortcut.WorkingDirectory = $installRoot
$shortcut.IconLocation = "$app,0"
$shortcut.Description = 'Claude Desktop Guardian 网络守护'
$shortcut.Save()

Write-Host '安装完成：Claude Desktop Guardian' -ForegroundColor Green

