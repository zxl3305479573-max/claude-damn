using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClaudeDesktopGuardian.Core;

public sealed record AccountOperationResult(bool Success, string Message);

/// <summary>
/// Transactional multi-account (A-D) snapshot isolation manager for Claude Desktop.
/// Archives active Claude data safely using .new/.previous staging, supports keep-in-workspace.txt
/// shared relative paths, and never deletes active data before target staging completes.
/// </summary>
public sealed class AccountSlotManager
{
    public static readonly IReadOnlyList<string> Slots = new[] { "A", "B", "C", "D" };

    private const string AccountOpMutexName = @"Local\ClaudeDesktopGuardian.AccountOp";

    private readonly string _baseDir;
    private readonly string? _claudeDataDirOverride;
    private readonly Func<bool>? _stopClaudeOverride;
    private readonly Func<bool>? _startClaudeOverride;
    private readonly Func<bool>? _stopCliOverride;

    public AccountSlotManager(
        string? baseDir = null,
        string? claudeDataDir = null,
        Func<bool>? stopClaudeOverride = null,
        Func<bool>? startClaudeOverride = null,
        Func<bool>? stopCliOverride = null)
    {
        _baseDir = baseDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ClaudeDesktopGuardian");
        _claudeDataDirOverride = claudeDataDir;
        _stopClaudeOverride = stopClaudeOverride;
        _startClaudeOverride = startClaudeOverride;
        _stopCliOverride = stopCliOverride;
    }

    private string ClaudeDataDir => _claudeDataDirOverride ?? ClaudeInstallDiscovery.Discover(forceRefresh: true).ActiveDataPath;

    public string AccountsRoot => Path.Combine(_baseDir, "accounts");
    public string KeepFilePath => Path.Combine(_baseDir, "keep-in-workspace.txt");
    private string CurrentSlotPath => Path.Combine(_baseDir, "current-account.txt");
    private string StagingRoot => Path.Combine(_baseDir, "staging");
    private string KeepStagePath => Path.Combine(_baseDir, "keep-stage");

    public static bool IsValidSlot(string? slot) =>
        !string.IsNullOrWhiteSpace(slot) && Regex.IsMatch(slot.Trim(), "^[A-D]$");

    public string GetCurrentSlot()
    {
        try
        {
            if (!File.Exists(CurrentSlotPath))
            {
                return string.Empty;
            }

            var value = File.ReadAllText(CurrentSlotPath, Encoding.ASCII).Trim();
            return IsValidSlot(value) ? value : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    public IReadOnlyList<AccountSlotInfo> ListSlots()
    {
        var current = GetCurrentSlot();
        var list = new List<AccountSlotInfo>(4);
        foreach (var slot in Slots)
        {
            var dir = Path.Combine(AccountsRoot, slot);
            var exists = Directory.Exists(dir);
            long size = exists ? CliInspector.MeasureDirectoryBytes(dir) : 0;
            DateTimeOffset? lastWrite = exists ? new DirectoryInfo(dir).LastWriteTimeUtc : null;
            list.Add(new AccountSlotInfo(slot, string.Equals(current, slot, StringComparison.Ordinal), exists, size, lastWrite));
        }

        return list;
    }

    public string ReadKeepPathsText()
    {
        try
        {
            return File.Exists(KeepFilePath) ? File.ReadAllText(KeepFilePath, Encoding.UTF8) : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    public void SaveKeepPathsText(string content)
    {
        Directory.CreateDirectory(_baseDir);
        File.WriteAllText(KeepFilePath, content ?? string.Empty, new UTF8Encoding(false));
    }

    public AccountOperationResult SwitchToSlot(
        string targetSlot,
        bool environmentHealthy,
        string? environmentBlockReason,
        bool launchAfterSwitch = true) =>
        RunSerialized(() => SwitchToSlotCore(targetSlot, environmentHealthy, environmentBlockReason, launchAfterSwitch));

    private AccountOperationResult SwitchToSlotCore(
        string targetSlot,
        bool environmentHealthy,
        string? environmentBlockReason,
        bool launchAfterSwitch)
    {
        var claudeDataDir = ClaudeDataDir;
        targetSlot = targetSlot?.Trim().ToUpperInvariant() ?? string.Empty;
        if (!IsValidSlot(targetSlot))
        {
            return new AccountOperationResult(false, "账号槽位必须是 A、B、C 或 D");
        }

        if (!environmentHealthy)
        {
            var reason = string.IsNullOrWhiteSpace(environmentBlockReason)
                ? "当前环境检查未通过"
                : environmentBlockReason;
            return new AccountOperationResult(false, $"Fail-Closed 拦截：拒绝在异常环境下切换账号（{reason}）");
        }

        Directory.CreateDirectory(AccountsRoot);
        Directory.CreateDirectory(StagingRoot);

        var current = GetCurrentSlot();
        var justArchivedFirstRun = false;

        // First run: adopt existing Claude data as slot A
        if (string.IsNullOrEmpty(current) &&
            Directory.Exists(claudeDataDir) &&
            Directory.EnumerateFileSystemEntries(claudeDataDir).Any())
        {
            if (!StopClaudeGracefully())
            {
                return new AccountOperationResult(false, "Claude 未能退出，请手动关闭 Claude 后重试");
            }

            if (!StopClaudeCliGracefully())
            {
                return new AccountOperationResult(false, "检测到当前用户的 Claude Code CLI 仍在运行（10 秒内未退出），已中止切换，桌面数据与当前槽位未改动");
            }

            var stageKeep = StageKeepPaths();
            if (!stageKeep.Success)
            {
                return stageKeep;
            }

            var saveFirst = SaveAccount("A");
            if (!saveFirst.Success)
            {
                TryDeleteDirectory(KeepStagePath);
                return saveFirst;
            }

            WriteAtomicCurrent("A");
            current = "A";
            justArchivedFirstRun = true;
        }

        if (string.Equals(current, targetSlot, StringComparison.Ordinal))
        {
            if (!Directory.Exists(claudeDataDir))
            {
                if (!Directory.Exists(Path.Combine(AccountsRoot, targetSlot)))
                {
                    return new AccountOperationResult(false, $"账号 {targetSlot} 数据目录与归档均缺失，已中止");
                }

                var loadSame = LoadAccount(targetSlot);
                if (!loadSame.Success)
                {
                    return loadSame;
                }
            }

            var restoreSame = RestoreKeepPaths();
            if (!restoreSame.Success)
            {
                return restoreSame;
            }

            if (launchAfterSwitch)
            {
                StartClaude();
            }

            return new AccountOperationResult(true, $"当前已是账号 {targetSlot}" + (justArchivedFirstRun ? "（已将现有登录收编为账号 A）" : string.Empty));
        }

        if (!StopClaudeGracefully())
        {
            return new AccountOperationResult(false, "Claude 未能退出，请手动关闭 Claude 后重试");
        }

        if (!StopClaudeCliGracefully())
        {
            return new AccountOperationResult(false, "检测到当前用户的 Claude Code CLI 仍在运行（10 秒内未退出），已中止切换，桌面数据与当前槽位未改动");
        }

        if (!justArchivedFirstRun && !string.IsNullOrEmpty(current) && Directory.Exists(claudeDataDir))
        {
            var stageKeep = StageKeepPaths();
            if (!stageKeep.Success)
            {
                return stageKeep;
            }

            var saveCurrent = SaveAccount(current);
            if (!saveCurrent.Success)
            {
                TryDeleteDirectory(KeepStagePath);
                return saveCurrent;
            }
        }

        var loadResult = Directory.Exists(Path.Combine(AccountsRoot, targetSlot))
            ? LoadAccount(targetSlot)
            : InitializeEmptySlot(targetSlot);
        if (!loadResult.Success)
        {
            return loadResult;
        }

        var restoreKeep = RestoreKeepPaths();
        if (!restoreKeep.Success)
        {
            return restoreKeep;
        }

        var launched = !launchAfterSwitch || StartClaude();
        var suffix = launchAfterSwitch
            ? launched ? "并已启动 Claude" : "（未找到 Claude 启动入口，请手动启动）"
            : string.Empty;
        return new AccountOperationResult(true, $"已切换到账号 {targetSlot} {suffix}".Trim());
    }

    public AccountOperationResult ExportEncryptedSnapshot(string slot, string destinationFile, string password) =>
        RunSerialized(() => ExportEncryptedSnapshotCore(slot, destinationFile, password));

    private AccountOperationResult ExportEncryptedSnapshotCore(string slot, string destinationFile, string password)
    {
        slot = slot?.Trim().ToUpperInvariant() ?? string.Empty;
        if (!IsValidSlot(slot))
        {
            return new AccountOperationResult(false, "账号槽位必须是 A、B、C 或 D");
        }

        var source = Path.Combine(AccountsRoot, slot);
        if (!Directory.Exists(source))
        {
            return new AccountOperationResult(false, $"账号 {slot} 没有已归档快照");
        }

        if (string.Equals(GetCurrentSlot(), slot, StringComparison.Ordinal))
        {
            return new AccountOperationResult(false, $"账号 {slot} 正在使用中，请先切换到其他槽位完成归档后再导出");
        }

        if (string.IsNullOrWhiteSpace(destinationFile))
        {
            return new AccountOperationResult(false, "请指定快照导出文件路径");
        }

        var fullDest = Path.GetFullPath(destinationFile);
        if (File.Exists(fullDest))
        {
            return new AccountOperationResult(false, "目标文件已存在，请换一个文件名");
        }

        if (string.IsNullOrEmpty(password) || password.Length < 8)
        {
            return new AccountOperationResult(false, "快照密码至少需要 8 位");
        }

        var tempZip = Path.Combine(Path.GetTempPath(), $"cdg-export-{Guid.NewGuid():N}.zip");
        try
        {
            EncryptedSnapshotService.CreateNormalizedZip(source, tempZip, slot);
            EncryptedSnapshotService.ProtectFile(tempZip, fullDest, password);
            return new AccountOperationResult(true, $"账号 {slot} 已加密导出到 {fullDest}");
        }
        catch (Exception ex)
        {
            try { File.Delete(fullDest); } catch { }
            return new AccountOperationResult(false, $"导出失败：{ex.Message}");
        }
        finally
        {
            try { File.Delete(tempZip); } catch { }
        }
    }

    public AccountOperationResult ImportEncryptedSnapshot(string sourceFile, string targetSlot, string password) =>
        RunSerialized(() => ImportEncryptedSnapshotCore(sourceFile, targetSlot, password));

    private AccountOperationResult ImportEncryptedSnapshotCore(string sourceFile, string targetSlot, string password)
    {
        targetSlot = targetSlot?.Trim().ToUpperInvariant() ?? string.Empty;
        if (!IsValidSlot(targetSlot))
        {
            return new AccountOperationResult(false, "账号槽位必须是 A、B、C 或 D");
        }

        if (string.IsNullOrWhiteSpace(sourceFile) || !File.Exists(sourceFile))
        {
            return new AccountOperationResult(false, "找不到指定的 .csnap 快照文件");
        }

        if (string.IsNullOrEmpty(password))
        {
            return new AccountOperationResult(false, "请输入快照密码");
        }

        var destination = Path.Combine(AccountsRoot, targetSlot);
        var stage = Path.Combine(AccountsRoot, targetSlot + ".new");
        var previous = Path.Combine(AccountsRoot, targetSlot + ".previous");
        foreach (var path in new[] { destination, stage, previous })
        {
            if (Directory.Exists(path) || File.Exists(path))
            {
                return new AccountOperationResult(false, $"账号 {targetSlot} 已有快照或待恢复数据（{path}），拒绝覆盖");
            }
        }

        var tempZip = Path.Combine(Path.GetTempPath(), $"cdg-import-{Guid.NewGuid():N}.zip");
        var extractDir = Path.Combine(Path.GetTempPath(), $"cdg-extract-{Guid.NewGuid():N}");
        var ownsStage = false;
        try
        {
            if (!EncryptedSnapshotService.UnprotectFile(sourceFile, tempZip, password))
            {
                return new AccountOperationResult(false, "密码错误或快照文件已被篡改/损坏");
            }

            EncryptedSnapshotService.ValidateSnapshotArchive(tempZip, targetSlot);
            Directory.CreateDirectory(extractDir);
            EncryptedSnapshotService.ExtractSnapshotArchive(tempZip, extractDir);

            Directory.CreateDirectory(AccountsRoot);
            ownsStage = true;
            CopyDirectorySafe(extractDir, stage);
            Directory.Move(stage, destination);
            ownsStage = false;
            return new AccountOperationResult(true, $"已成功导入加密快照到槽位 {targetSlot}（切换时生效）");
        }
        catch (Exception ex)
        {
            if (ownsStage)
            {
                TryDeleteDirectory(stage);
            }

            return new AccountOperationResult(false, $"导入失败：{ex.Message}");
        }
        finally
        {
            try { File.Delete(tempZip); } catch { }
            TryDeleteDirectory(extractDir);
        }
    }

    private AccountOperationResult RunSerialized(Func<AccountOperationResult> operation)
    {
        Mutex? mutex = null;
        var acquired = false;
        try
        {
            mutex = new Mutex(initiallyOwned: false, name: AccountOpMutexName);
            try
            {
                acquired = mutex.WaitOne(0);
            }
            catch (AbandonedMutexException)
            {
                acquired = true;
            }

            if (!acquired)
            {
                return new AccountOperationResult(false, "另一个账号切换或快照任务正在执行，请等待完成后重试");
            }

            return operation();
        }
        finally
        {
            if (acquired && mutex is not null)
            {
                try { mutex.ReleaseMutex(); } catch { }
            }

            mutex?.Dispose();
        }
    }

    private AccountOperationResult SaveAccount(string slot)
    {
        var claudeDataDir = ClaudeDataDir;
        var stage = Path.Combine(AccountsRoot, slot + ".new");
        var currentDir = Path.Combine(AccountsRoot, slot);
        var previous = Path.Combine(AccountsRoot, slot + ".previous");

        foreach (var p in new[] { stage, previous })
        {
            if (Directory.Exists(p) || File.Exists(p))
            {
                return new AccountOperationResult(false, $"账号 {slot} 存在待恢复快照（{p}），拒绝覆盖");
            }
        }

        try
        {
            CopyDirectorySafe(claudeDataDir, stage);
        }
        catch (Exception ex)
        {
            TryDeleteDirectory(stage);
            return new AccountOperationResult(false, $"账号 {slot} 归档复制失败，当前数据未改动：{ex.Message}");
        }

        var movedPrevious = false;
        if (Directory.Exists(currentDir))
        {
            try
            {
                Directory.Move(currentDir, previous);
                movedPrevious = true;
            }
            catch (Exception ex)
            {
                TryDeleteDirectory(stage);
                return new AccountOperationResult(false, $"账号 {slot} 旧快照无法安全转存：{ex.Message}");
            }
        }

        try
        {
            Directory.Move(stage, currentDir);
        }
        catch (Exception ex)
        {
            if (movedPrevious && Directory.Exists(previous))
            {
                try { Directory.Move(previous, currentDir); } catch { }
            }

            TryDeleteDirectory(stage);
            return new AccountOperationResult(false, $"账号 {slot} 归档提交失败，已回滚旧快照：{ex.Message}");
        }

        if (movedPrevious)
        {
            TryDeleteDirectory(previous);
        }

        return new AccountOperationResult(true, $"已存档账号 {slot}");
    }

    private AccountOperationResult LoadAccount(string slot)
    {
        var source = Path.Combine(AccountsRoot, slot);
        var stage = GetSwitchStagePath();
        if (!Directory.Exists(source))
        {
            return new AccountOperationResult(false, $"账号 {slot} 没有可用快照");
        }

        if (Directory.Exists(stage))
        {
            return new AccountOperationResult(false, $"存在待恢复暂存目录（{stage}），拒绝覆盖");
        }

        try
        {
            CopyDirectorySafe(source, stage);
        }
        catch (Exception ex)
        {
            TryDeleteDirectory(stage);
            return new AccountOperationResult(false, $"账号 {slot} 快照载入失败，当前数据未改动：{ex.Message}");
        }

        return SwitchDataDirectory(stage, slot);
    }

    private AccountOperationResult InitializeEmptySlot(string slot)
    {
        var stage = GetSwitchStagePath();
        if (Directory.Exists(stage))
        {
            return new AccountOperationResult(false, $"存在待恢复暂存目录（{stage}），拒绝覆盖");
        }

        Directory.CreateDirectory(stage);
        return SwitchDataDirectory(stage, slot);
    }

    private AccountOperationResult SwitchDataDirectory(string stagePath, string targetSlot)
    {
        var claudeDataDir = ClaudeDataDir;
        var oldPath = GetSwitchPreviousPath();
        var cleanupCheck = ResolveOwnedSwitchCleanup(oldPath);
        if (!cleanupCheck.Success)
        {
            TryDeleteDirectory(stagePath);
            return cleanupCheck;
        }

        if (Directory.Exists(oldPath))
        {
            TryDeleteDirectory(stagePath);
            return new AccountOperationResult(false, $"存在待恢复数据（{oldPath}），拒绝覆盖");
        }

        var parentDir = Path.GetDirectoryName(claudeDataDir);
        if (!string.IsNullOrWhiteSpace(parentDir))
        {
            Directory.CreateDirectory(parentDir);
        }

        if (Directory.Exists(claudeDataDir))
        {
            try
            {
                Directory.Move(claudeDataDir, oldPath);
            }
            catch (Exception ex)
            {
                TryDeleteDirectory(stagePath);
                return new AccountOperationResult(false, $"当前 Claude 数据目录被占用或无法移开：{ex.Message}");
            }
        }

        try
        {
            Directory.Move(stagePath, claudeDataDir);
        }
        catch (Exception ex)
        {
            if (Directory.Exists(oldPath))
            {
                try { Directory.Move(oldPath, claudeDataDir); }
                catch (Exception rollbackEx)
                {
                    return new AccountOperationResult(false, $"新数据提交失败且自动回滚失败（原数据保留在 {oldPath}）：{rollbackEx.Message}");
                }
            }

            return new AccountOperationResult(false, $"新数据提交失败，已安全回滚：{ex.Message}");
        }

        try
        {
            WriteAtomicCurrent(targetSlot);
        }
        catch (Exception ex)
        {
            try
            {
                if (Directory.Exists(claudeDataDir)) Directory.Move(claudeDataDir, stagePath);
                if (Directory.Exists(oldPath)) Directory.Move(oldPath, claudeDataDir);
            }
            catch
            {
                return new AccountOperationResult(false, $"账号指针写入失败且回滚未完成，恢复材料保留在 {stagePath} 和 {oldPath}：{ex.Message}");
            }

            return new AccountOperationResult(false, $"账号指针写入失败，已回滚：{ex.Message}");
        }

        if (Directory.Exists(oldPath))
        {
            try
            {
                Directory.Delete(oldPath, recursive: true);
            }
            catch
            {
                RegisterOwnedSwitchCleanup(oldPath, targetSlot);
            }
        }

        return new AccountOperationResult(true, "数据目录换位完成");
    }

    private string GetSwitchStagePath()
    {
        var claudeDataDir = ClaudeDataDir;
        var baseRoot = Path.GetPathRoot(Path.GetFullPath(_baseDir));
        var dataRoot = Path.GetPathRoot(Path.GetFullPath(claudeDataDir));
        return string.Equals(baseRoot, dataRoot, StringComparison.OrdinalIgnoreCase)
            ? Path.Combine(StagingRoot, "Claude.new")
            : claudeDataDir + ".new";
    }

    private string GetSwitchPreviousPath()
    {
        var claudeDataDir = ClaudeDataDir;
        var baseRoot = Path.GetPathRoot(Path.GetFullPath(_baseDir));
        var dataRoot = Path.GetPathRoot(Path.GetFullPath(claudeDataDir));
        return string.Equals(baseRoot, dataRoot, StringComparison.OrdinalIgnoreCase)
            ? Path.Combine(StagingRoot, "Claude.old")
            : claudeDataDir + ".old";
    }

    private void WriteAtomicCurrent(string slot)
    {
        var tmp = Path.Combine(_baseDir, $".current-{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllText(tmp, slot, Encoding.ASCII);
            File.Move(tmp, CurrentSlotPath, true);
        }
        finally
        {
            if (File.Exists(tmp))
            {
                try { File.Delete(tmp); } catch { }
            }
        }
    }

    private void RegisterOwnedSwitchCleanup(string oldPath, string targetSlot)
    {
        try
        {
            Directory.CreateDirectory(StagingRoot);
            var marker = Path.Combine(StagingRoot, "cleanup.json");
            var payload = JsonSerializer.Serialize(new { version = 1, path = oldPath, target = targetSlot });
            File.WriteAllText(marker, payload, new UTF8Encoding(false));
        }
        catch
        {
        }
    }

    private AccountOperationResult ResolveOwnedSwitchCleanup(string oldPath)
    {
        var marker = Path.Combine(StagingRoot, "cleanup.json");
        if (!Directory.Exists(oldPath) && !File.Exists(marker))
        {
            return new AccountOperationResult(true, string.Empty);
        }

        var current = GetCurrentSlot();
        var valid = false;
        if (File.Exists(marker))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(marker, Encoding.UTF8));
                var root = doc.RootElement;
                valid = root.TryGetProperty("version", out var v) && v.GetInt32() == 1 &&
                        root.TryGetProperty("path", out var p) && string.Equals(p.GetString(), oldPath, StringComparison.OrdinalIgnoreCase) &&
                        root.TryGetProperty("target", out var t) && string.Equals(t.GetString(), current, StringComparison.Ordinal);
            }
            catch
            {
                valid = false;
            }
        }

        if (valid)
        {
            if (!Directory.Exists(oldPath))
            {
                try { File.Delete(marker); } catch { }
                return new AccountOperationResult(true, string.Empty);
            }

            try
            {
                Directory.Delete(oldPath, recursive: true);
                File.Delete(marker);
                return new AccountOperationResult(true, string.Empty);
            }
            catch
            {
                return new AccountOperationResult(false, $"已确认归属的旧目录仍被占用无法清理：{oldPath}，请关闭占用程序后重试");
            }
        }

        if (Directory.Exists(oldPath))
        {
            return new AccountOperationResult(false, $"存在待恢复数据，拒绝覆盖：{oldPath}（请确认归属后手动处理）");
        }

        return new AccountOperationResult(true, string.Empty);
    }

    public bool IsKeepPathSafe(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath))
        {
            return false;
        }

        var rel = relativePath.Trim().Replace('/', '\\').TrimEnd('\\');
        while (rel.StartsWith(".\\", StringComparison.Ordinal))
        {
            rel = rel[2..];
        }

        if (string.IsNullOrEmpty(rel) || rel == "." || Path.IsPathRooted(rel) || Regex.IsMatch(rel, @"^[A-Za-z]:"))
        {
            return false;
        }

        var parts = rel.Split('\\');
        if (parts.Any(part => part is ".." or ""))
        {
            return false;
        }

        var prefix = ClaudeDataDir;
        foreach (var part in parts)
        {
            prefix = Path.Combine(prefix, part);
            if (File.Exists(prefix) || Directory.Exists(prefix))
            {
                if ((File.GetAttributes(prefix) & FileAttributes.ReparsePoint) != 0)
                {
                    return false;
                }
            }
        }

        return true;
    }

    private AccountOperationResult StageKeepPaths()
    {
        var claudeDataDir = ClaudeDataDir;
        if (!File.Exists(KeepFilePath))
        {
            return new AccountOperationResult(true, string.Empty);
        }

        if (Directory.Exists(KeepStagePath))
        {
            return new AccountOperationResult(false, $"跨账号共享暂存目录已存在（{KeepStagePath}），请检查上次中断的切换");
        }

        var created = false;
        var count = 0;
        try
        {
            foreach (var raw in File.ReadAllLines(KeepFilePath, Encoding.UTF8))
            {
                var rel = raw.Trim();
                if (string.IsNullOrEmpty(rel) || rel.StartsWith('#'))
                {
                    continue;
                }

                if (!IsKeepPathSafe(rel))
                {
                    continue;
                }

                var normalized = rel.Replace('/', '\\').TrimEnd('\\');
                while (normalized.StartsWith(".\\", StringComparison.Ordinal))
                {
                    normalized = normalized[2..];
                }

                var source = Path.Combine(claudeDataDir, normalized);
                if (!File.Exists(source) && !Directory.Exists(source))
                {
                    continue;
                }

                var dest = Path.Combine(KeepStagePath, normalized);
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                created = true;
                if (Directory.Exists(source))
                {
                    CopyDirectorySafe(source, dest);
                }
                else
                {
                    File.Copy(source, dest, overwrite: true);
                }

                count++;
            }
        }
        catch (Exception ex)
        {
            if (created)
            {
                TryDeleteDirectory(KeepStagePath);
            }

            return new AccountOperationResult(false, $"跨账号共享路径暂存失败：{ex.Message}");
        }

        if (count == 0 && created)
        {
            TryDeleteDirectory(KeepStagePath);
        }

        return new AccountOperationResult(true, string.Empty);
    }

    private AccountOperationResult RestoreKeepPaths()
    {
        if (!Directory.Exists(KeepStagePath))
        {
            return new AccountOperationResult(true, string.Empty);
        }

        try
        {
            CopyDirectorySafe(KeepStagePath, ClaudeDataDir);
            Directory.Delete(KeepStagePath, recursive: true);
            return new AccountOperationResult(true, string.Empty);
        }
        catch (Exception ex)
        {
            return new AccountOperationResult(false, $"跨账号共享路径还原失败（暂存保留在 {KeepStagePath}）：{ex.Message}");
        }
    }

    private bool StopClaudeCliGracefully()
    {
        if (_stopCliOverride is not null)
        {
            return _stopCliOverride();
        }

        if (!OperatingSystem.IsWindows())
        {
            return true;
        }

        var initial = WindowsProcessInspector.FindCurrentUserCliProcesses();
        if (initial.Count == 0)
        {
            return true;
        }

        var currentSession = Process.GetCurrentProcess().SessionId;
        foreach (var info in initial)
        {
            try
            {
                using var proc = Process.GetProcessById(info.ProcessId);
                if (proc.SessionId == currentSession)
                {
                    proc.CloseMainWindow();
                }
            }
            catch
            {
            }
        }

        // Wait up to 10 seconds for CLI to exit gracefully; never force-kill CLI
        for (var i = 0; i < 20; i++)
        {
            if (WindowsProcessInspector.FindCurrentUserCliProcesses().Count == 0)
            {
                return true;
            }

            Thread.Sleep(500);
        }

        return WindowsProcessInspector.FindCurrentUserCliProcesses().Count == 0;
    }

    private bool StopClaudeGracefully()
    {
        if (_stopClaudeOverride is not null)
        {
            return _stopClaudeOverride();
        }

        var inspector = new WindowsProcessInspector();
        var targets = inspector.FindClaudeProcessTree();
        if (targets.Count == 0)
        {
            return true;
        }

        var currentSession = Process.GetCurrentProcess().SessionId;
        foreach (var info in targets)
        {
            try
            {
                using var proc = Process.GetProcessById(info.ProcessId);
                if (proc.SessionId == currentSession)
                {
                    proc.CloseMainWindow();
                }
            }
            catch
            {
            }
        }

        for (var i = 0; i < 10; i++)
        {
            if (inspector.FindClaudeProcessTree().Count == 0)
            {
                return true;
            }
            Thread.Sleep(500);
        }

        foreach (var info in inspector.FindClaudeProcessTree())
        {
            try
            {
                using var proc = Process.GetProcessById(info.ProcessId);
                if (proc.SessionId == currentSession)
                {
                    proc.Kill(true);
                }
            }
            catch
            {
            }
        }

        for (var i = 0; i < 10; i++)
        {
            if (inspector.FindClaudeProcessTree().Count == 0)
            {
                return true;
            }
            Thread.Sleep(500);
        }

        return false;
    }

    private bool StartClaude()
    {
        if (_startClaudeOverride is not null)
        {
            return _startClaudeOverride();
        }

        var target = ClaudeInstallDiscovery.FindClaudeLaunchTarget();
        if (string.IsNullOrWhiteSpace(target))
        {
            return false;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = target,
                UseShellExecute = true
            });
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void CopyDirectorySafe(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);
        foreach (var dir in Directory.EnumerateDirectories(sourceDir, "*", SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0)
            {
                continue;
            }

            var rel = Path.GetRelativePath(sourceDir, dir);
            Directory.CreateDirectory(Path.Combine(destDir, rel));
        }

        foreach (var file in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
            {
                continue;
            }

            var rel = Path.GetRelativePath(sourceDir, file);
            var target = Path.Combine(destDir, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch
        {
        }
    }
}
