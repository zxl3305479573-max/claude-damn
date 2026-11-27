[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedSha256,
    [Parameter(Mandatory = $true)]
    [string]$ReadyPath,
    [Parameter(Mandatory = $true)]
    [int]$ParentProcessId
)

$ErrorActionPreference = 'Stop'
$installRoot = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')
$separator = [string][IO.Path]::DirectorySeparatorChar
$parent = $null
$ownerProfile = $null
$updatesRoot = $null
$packageDirectory = $null
$newRoot = $null
$backupRoot = $null
$failedRoot = $null
$backupMoved = $false
$taskNames = @()
$taskActions = @{}
$taskEnabled = @{}

function Test-PathWithin([string]$Root, [string]$Candidate) {
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $fullCandidate = [IO.Path]::GetFullPath($Candidate)
    return $fullCandidate.StartsWith($fullRoot + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Get-InstalledGuardianProcesses {
    $names = @(
        'ClaudeDesktopGuardian.App.exe',
        'ClaudeDesktopGuardian.Helper.exe',
        'ClaudeDesktopGuardian.Cli.exe'
    )
    return @(Get-CimInstance Win32_Process | Where-Object {
        $_.Name -in $names -and
        -not [string]::IsNullOrWhiteSpace($_.ExecutablePath) -and
        (Test-PathWithin $installRoot $_.ExecutablePath)
    })
}

function Start-PreviousTasks {
    foreach ($taskName in @('ClaudeDesktopGuardian.Helper', 'ClaudeDesktopGuardian')) {
        if ($taskNames -contains $taskName -and $taskEnabled[$taskName]) {
            Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        }
    }
}

function Show-UpdateFailure([string]$Message) {
    try {
        Add-Type -AssemblyName PresentationFramework
        [System.Windows.MessageBox]::Show(
            $Message,
            'Claude Desktop Guardian 更新失败',
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning) | Out-Null
    }
    catch {
        Write-Error $Message
    }
}

try {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '应用更新需要管理员权限。'
    }

    $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $ParentProcessId"
    $expectedAppPath = Join-Path $installRoot 'ClaudeDesktopGuardian.App.exe'
    if (-not $parent -or [string]::IsNullOrWhiteSpace($parent.ExecutablePath) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals(
            [IO.Path]::GetFullPath($parent.ExecutablePath), $expectedAppPath)) {
        throw '更新请求的 Guardian 进程无效。'
    }

    $ownerSidResult = Invoke-CimMethod -InputObject $parent -MethodName GetOwnerSid
    $ownerProfile = Get-CimInstance Win32_UserProfile -Filter "SID = '$($ownerSidResult.Sid)'"
    if (-not $ownerProfile -or [string]::IsNullOrWhiteSpace($ownerProfile.LocalPath)) {
        throw '无法确认 Guardian 用户的更新目录。'
    }

    $updatesRoot = [IO.Path]::GetFullPath((Join-Path $ownerProfile.LocalPath 'AppData\Local\ClaudeDesktopGuardian\updates')).TrimEnd('\')
    $packagePath = [IO.Path]::GetFullPath($PackagePath)
    $packageDirectory = [IO.Path]::GetDirectoryName($packagePath).TrimEnd('\')
    $packageName = [IO.Path]::GetFileName($packagePath)
    if (-not (Test-PathWithin $updatesRoot $packageDirectory) -or
        [IO.Path]::GetFileName($packageDirectory) -notmatch '^[0-9a-fA-F]{32}$' -or
        $packageName -notmatch '^ClaudeDesktopGuardian-\d+\.\d+\.\d+-windows-x64\.zip$') {
        throw '更新包不在 Guardian 的专属暂存目录中。'
    }

    $readyPath = [IO.Path]::GetFullPath($ReadyPath)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals(
        $readyPath,
        (Join-Path $packageDirectory 'updater-ready.txt'))) {
        throw '更新器就绪标记路径无效。'
    }
    if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
        -not (Test-Path -LiteralPath $packagePath -PathType Leaf) -or
        (Get-Item -LiteralPath $packagePath).Length -gt 536870912) {
        throw '更新包缺失、过大或 SHA-256 参数无效。'
    }

    $actualHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($actualHash, $ExpectedSha256)) {
        throw '更新包 SHA-256 复核失败。'
    }
    [IO.File]::WriteAllText($readyPath, 'ready', [Text.Encoding]::ASCII)

    try {
        Wait-Process -Id $ParentProcessId -Timeout 180 -ErrorAction SilentlyContinue
    }
    catch {
    }
    if (Get-Process -Id $ParentProcessId -ErrorAction SilentlyContinue) {
        throw 'Guardian 尚未安全退出，更新已取消。'
    }

    foreach ($taskName in @('ClaudeDesktopGuardian', 'ClaudeDesktopGuardian.Helper')) {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            $taskNames += $taskName
            $taskActions[$taskName] = @($task.Actions)
            $taskEnabled[$taskName] = $task.State -ne 'Disabled'
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        }
    }

    $activeProcesses = Get-InstalledGuardianProcesses
    if ($activeProcesses | Where-Object { $_.Name -in @('ClaudeDesktopGuardian.App.exe', 'ClaudeDesktopGuardian.Cli.exe') }) {
        throw '其他 Guardian 界面或 CLI 进程仍在运行，更新已取消。'
    }
    foreach ($helper in @($activeProcesses | Where-Object { $_.Name -eq 'ClaudeDesktopGuardian.Helper.exe' })) {
        Stop-Process -Id $helper.ProcessId -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $helper.ProcessId -Timeout 10 -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 500
    if (Get-InstalledGuardianProcesses) {
        throw 'Guardian 助手仍在运行，更新已取消。'
    }

    $actualHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($actualHash, $ExpectedSha256)) {
        throw 'Guardian 退出后更新包已变化，SHA-256 复核失败。'
    }

    $transactionId = [Guid]::NewGuid().ToString('N')
    $newRoot = "$installRoot.new.$transactionId"
    $backupRoot = "$installRoot.rollback.$transactionId"
    $failedRoot = "$installRoot.failed.$transactionId"
    New-Item -ItemType Directory -Path $newRoot | Out-Null

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($packagePath)
    try {
        if ($archive.Entries.Count -gt 10000) {
            throw '更新包文件数量超过允许限制。'
        }

        $expandedBytes = 0L
        foreach ($entry in $archive.Entries) {
            $expandedBytes += $entry.Length
            if ([IO.Path]::IsPathRooted($entry.FullName) -or $entry.FullName.Contains(':') -or
                ((($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000)) {
                throw '更新包包含绝对路径、备用数据流或符号链接。'
            }

            $entryPath = [IO.Path]::GetFullPath([IO.Path]::Combine($newRoot, $entry.FullName.Replace('/', $separator)))
            if (-not $entryPath.StartsWith($newRoot + $separator, [StringComparison]::OrdinalIgnoreCase) -or
                $expandedBytes -gt 1073741824) {
                throw '更新包路径越界或解压后体积超过限制。'
            }
        }
    }
    finally {
        $archive.Dispose()
    }

    [IO.Compression.ZipFile]::ExtractToDirectory($packagePath, $newRoot)
    foreach ($requiredFile in @(
        'ClaudeDesktopGuardian.App.exe',
        'ClaudeDesktopGuardian.Helper.exe',
        'ClaudeDesktopGuardian.Cli.exe',
        'apply-update.ps1',
        'VERSION')) {
        if (-not (Test-Path -LiteralPath (Join-Path $newRoot $requiredFile) -PathType Leaf)) {
            throw "更新包缺少必需文件：$requiredFile"
        }
    }

    $version = (Get-Content -LiteralPath (Join-Path $newRoot 'VERSION') -Raw).Trim()
    if ($version -notmatch '^\d+\.\d+\.\d+$' -or
        $packageName -ne "ClaudeDesktopGuardian-$version-windows-x64.zip") {
        throw '更新包版本号与资产名称不一致。'
    }

    Move-Item -LiteralPath $installRoot -Destination $backupRoot
    $backupMoved = $true
    Move-Item -LiteralPath $newRoot -Destination $installRoot

    if ($taskNames -contains 'ClaudeDesktopGuardian.Helper') {
        Set-ScheduledTask -TaskName 'ClaudeDesktopGuardian.Helper' -Action (
            New-ScheduledTaskAction -Execute (Join-Path $installRoot 'ClaudeDesktopGuardian.Helper.exe')) | Out-Null
    }
    if ($taskNames -contains 'ClaudeDesktopGuardian') {
        Set-ScheduledTask -TaskName 'ClaudeDesktopGuardian' -Action (
            New-ScheduledTaskAction -Execute (Join-Path $installRoot 'ClaudeDesktopGuardian.App.exe')) | Out-Null
    }

    foreach ($taskName in @('ClaudeDesktopGuardian.Helper', 'ClaudeDesktopGuardian')) {
        if ($taskNames -contains $taskName -and $taskEnabled[$taskName]) {
            Start-ScheduledTask -TaskName $taskName
        }
    }

    $startupDeadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    while ([DateTimeOffset]::UtcNow -lt $startupDeadline) {
        $activeProcesses = Get-InstalledGuardianProcesses
        $helperReady = -not ($taskNames -contains 'ClaudeDesktopGuardian.Helper') -or
            -not $taskEnabled['ClaudeDesktopGuardian.Helper'] -or
            [bool]($activeProcesses | Where-Object { $_.Name -eq 'ClaudeDesktopGuardian.Helper.exe' })
        $appReady = -not ($taskNames -contains 'ClaudeDesktopGuardian') -or
            -not $taskEnabled['ClaudeDesktopGuardian'] -or
            [bool]($activeProcesses | Where-Object { $_.Name -eq 'ClaudeDesktopGuardian.App.exe' })
        if ($helperReady -and $appReady) {
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $helperReady -or -not $appReady) {
        throw '更新后的 Guardian 启动验证失败。'
    }

    Remove-Item -LiteralPath $packageDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "Claude Desktop Guardian v$version 更新完成；回滚版本保留在 $backupRoot。"
}
catch {
    $failure = $_.Exception.Message
    if ($backupMoved -and (Test-Path -LiteralPath $backupRoot -PathType Container)) {
        try {
            foreach ($taskName in @('ClaudeDesktopGuardian', 'ClaudeDesktopGuardian.Helper')) {
                if ($taskNames -contains $taskName) {
                    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                }
            }
            foreach ($process in (Get-InstalledGuardianProcesses)) {
                Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
                Wait-Process -Id $process.ProcessId -Timeout 10 -ErrorAction SilentlyContinue
            }
            if (Test-Path -LiteralPath $installRoot -PathType Container) {
                Move-Item -LiteralPath $installRoot -Destination $failedRoot
            }
            Move-Item -LiteralPath $backupRoot -Destination $installRoot
            foreach ($taskName in $taskNames) {
                if ($taskActions.ContainsKey($taskName) -and $taskActions[$taskName].Count -gt 0) {
                    Set-ScheduledTask -TaskName $taskName -Action $taskActions[$taskName] | Out-Null
                }
            }
        }
        catch {
            $failure = "$failure`n自动回滚失败：$($_.Exception.Message)`n旧版本位置：$backupRoot"
        }
    }

    if ($newRoot -and (Test-Path -LiteralPath $newRoot -PathType Container)) {
        Remove-Item -LiteralPath $newRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    Start-PreviousTasks
    Show-UpdateFailure $failure
    exit 1
}
