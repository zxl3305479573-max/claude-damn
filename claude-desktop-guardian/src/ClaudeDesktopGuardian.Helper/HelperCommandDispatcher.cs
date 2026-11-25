using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ClaudeDesktopGuardian.Core;

namespace ClaudeDesktopGuardian.Helper;

internal sealed record HelperFirewallStatus(
    bool ApiOk,
    int ActiveRuleCount,
    string Detail);

internal sealed record HelperWfpStatus(
    string State,
    string Detail,
    int ExecutableCount);

internal sealed record HelperWfpEnableResult(
    bool Success,
    string Detail,
    int PathCount,
    int TerminatedCount,
    int RemainingCount);

internal sealed record HelperRequest(
    string Token,
    string Command,
    IReadOnlyList<string>? Paths = null,
    IReadOnlyList<int>? ProcessIds = null,
    string? TimezoneId = null,
    string? AdapterGuid = null,
    bool AllowLoopback = false,
    IReadOnlyList<string>? AdapterNames = null);

internal interface IHelperSystemExecutor
{
    string CurrentUserSid { get; }
    int CurrentProcessId { get; }
    string GetExpectedToken();
    IReadOnlyList<string> DiscoverClaudeExecutablePaths();
    bool IsAllowedClaudePath(string path);
    IReadOnlyList<ProcessInfo> FindCurrentUserClaudeProcesses();
    Task<string> ReadTimezoneAsync();
    Task SetTimezoneAsync(string timezoneId);
    HelperFirewallStatus QueryFirewallGroupStatus(string groupName);
    Task ClearFirewallGroupAsync(string groupName);
    Task ClearAllGuardianFirewallRulesAsync(string rulePrefix);
    Task AddFirewallBlockRuleAsync(string ruleName, string groupName, string programPath);
    Task<(int Terminated, int Remaining)> TerminateProcessesAsync(IReadOnlyList<int> processIds);
    HelperWfpStatus QueryWfpDetailedSafe(string? adapterGuid, bool allowLoopback);
    HelperWfpStatus QueryWfpDetailed(string? adapterGuid, bool allowLoopback);
    Task<HelperWfpEnableResult> EnableWfpAsync(string? adapterGuid, IReadOnlyList<string> extraPaths, bool allowLoopback);
    void DisableWfp();
    Task FlushDnsAsync();
    Task DisableIpv6AdaptersAsync(IReadOnlyList<string> adapterNames);
}

internal sealed class HelperCommandDispatcher
{
    public const string RulePrefix = "ClaudeDesktopGuardian.";

    private readonly IHelperSystemExecutor _executor;

    public HelperCommandDispatcher(IHelperSystemExecutor executor)
    {
        _executor = executor;
    }

    public async Task<int> RunCleanupAllAsync(string? statePath)
    {
        var hadError = false;
        try
        {
            _executor.DisableWfp();
        }
        catch
        {
            hadError = true;
        }

        try
        {
            await _executor.ClearAllGuardianFirewallRulesAsync(RulePrefix);
        }
        catch
        {
            hadError = true;
        }

        try
        {
            var store = new GuardianStateStore(statePath);
            var state = store.Load();
            if (state.TimezoneOverrideActive &&
                !string.IsNullOrWhiteSpace(state.OriginalWindowsTimezone) &&
                WindowsTimezoneMapper.IsKnownWindowsId(state.OriginalWindowsTimezone))
            {
                await _executor.SetTimezoneAsync(state.OriginalWindowsTimezone);
                store.Save(state with
                {
                    Blocked = false,
                    TripReason = string.Empty,
                    BlockedAt = null,
                    TimezoneOverrideActive = false,
                    OriginalWindowsTimezone = null,
                    AppliedWindowsTimezone = null,
                    TimezoneOverrideAt = null
                });
            }
            else if (state.Blocked)
            {
                store.Save(state with { Blocked = false, TripReason = string.Empty, BlockedAt = null });
            }
        }
        catch
        {
            hadError = true;
        }

        return hadError ? 1 : 0;
    }

    public async Task<object> HandleLineAsync(string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return new { ok = false, error = "空命令" };
        }

        try
        {
            var request = JsonSerializer.Deserialize<HelperRequest>(
                line,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            var expectedToken = _executor.GetExpectedToken();
            if (request is null ||
                !ConstantTimeEquals(request.Token, expectedToken) ||
                request.Command is not (
                    "status" or
                    "apply-block" or
                    "clear-block" or
                    "terminate-tree" or
                    "get-timezone" or
                    "apply-timezone" or
                    "restore-timezone" or
                    "wfp-status" or
                    "wfp-enable" or
                    "wfp-disable" or
                    "flush-dns" or
                    "disable-ipv6-adapters"))
            {
                return new { ok = false, error = "未知命令或认证失败" };
            }

            var sid = string.IsNullOrWhiteSpace(_executor.CurrentUserSid) ? "unknown" : _executor.CurrentUserSid;
            var groupName = RulePrefix + sid.Replace('\\', '_');

            if (request.Command == "status")
            {
                var wfp = _executor.QueryWfpDetailedSafe(request.AdapterGuid, request.AllowLoopback);
                var fw = _executor.QueryFirewallGroupStatus(groupName);
                return new
                {
                    ok = true,
                    command = request.Command,
                    group = groupName,
                    timezoneId = await _executor.ReadTimezoneAsync(),
                    wfpState = wfp.State,
                    wfpDetail = wfp.Detail,
                    firewallApiOk = fw.ApiOk,
                    firewallActiveRuleCount = fw.ActiveRuleCount,
                    firewallDetail = fw.Detail,
                    helperDetail = $"受限命名管道在线（PID={_executor.CurrentProcessId}，组={groupName}）"
                };
            }

            var paths = (request.Paths ?? Array.Empty<string>())
                .Where(_executor.IsAllowedClaudePath)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (request.Command == "apply-block")
            {
                var discovered = _executor.DiscoverClaudeExecutablePaths();
                var allBlockPaths = paths
                    .Concat(discovered)
                    .Where(_executor.IsAllowedClaudePath)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                // Idempotent clear before re-adding so repeated triggers never pile up duplicate netsh rules
                await _executor.ClearFirewallGroupAsync(groupName);
                foreach (var path in allBlockPaths)
                {
                    var ruleName = groupName + "." + HashPath(path);
                    await _executor.AddFirewallBlockRuleAsync(ruleName, groupName, path);
                }

                return new { ok = true, command = request.Command, paths = allBlockPaths.Length, group = groupName };
            }

            if (request.Command == "clear-block")
            {
                await _executor.ClearFirewallGroupAsync(groupName);
                return new { ok = true, command = request.Command, paths = 0, group = groupName };
            }

            if (request.Command == "terminate-tree")
            {
                var requestedIds = (request.ProcessIds ?? Array.Empty<int>()).Distinct().ToHashSet();
                var ownedClaudeProcesses = _executor.FindCurrentUserClaudeProcesses();
                var allowedIds = ownedClaudeProcesses
                    .Where(p =>
                        requestedIds.Contains(p.ProcessId) &&
                        (string.IsNullOrEmpty(p.UserSid) || string.Equals(p.UserSid, sid, StringComparison.OrdinalIgnoreCase)))
                    .Select(p => p.ProcessId)
                    .Distinct()
                    .ToArray();
                var rejectedCount = requestedIds.Count - allowedIds.Length;
                var (terminated, remaining) = await _executor.TerminateProcessesAsync(allowedIds);
                return new
                {
                    ok = true,
                    command = request.Command,
                    terminated,
                    remaining,
                    rejected = rejectedCount
                };
            }

            if (request.Command == "get-timezone")
            {
                return new
                {
                    ok = true,
                    command = request.Command,
                    timezoneId = await _executor.ReadTimezoneAsync()
                };
            }

            if (request.Command is "apply-timezone" or "restore-timezone")
            {
                var timezoneId = request.TimezoneId?.Trim() ?? string.Empty;
                if (!WindowsTimezoneMapper.IsKnownWindowsId(timezoneId))
                {
                    return new { ok = false, error = "未知或不支持的 Windows 时区 ID" };
                }

                await _executor.SetTimezoneAsync(timezoneId);
                return new
                {
                    ok = true,
                    command = request.Command,
                    timezoneId = await _executor.ReadTimezoneAsync()
                };
            }

            if (request.Command == "wfp-status")
            {
                var wfp = _executor.QueryWfpDetailed(request.AdapterGuid, request.AllowLoopback);
                return new
                {
                    ok = true,
                    command = request.Command,
                    wfpState = wfp.State,
                    detail = wfp.Detail,
                    paths = wfp.ExecutableCount
                };
            }

            if (request.Command == "wfp-enable")
            {
                var result = await _executor.EnableWfpAsync(request.AdapterGuid, paths, request.AllowLoopback);
                if (!result.Success)
                {
                    return new { ok = false, error = result.Detail };
                }

                return new
                {
                    ok = true,
                    command = request.Command,
                    wfpState = "active",
                    paths = result.PathCount,
                    allowLoopback = request.AllowLoopback,
                    terminatedCount = result.TerminatedCount,
                    remainingCount = result.RemainingCount,
                    detail = result.Detail
                };
            }

            if (request.Command == "wfp-disable")
            {
                _executor.DisableWfp();
                return new
                {
                    ok = true,
                    command = request.Command,
                    wfpState = "off",
                    detail = "WFP 内核出站锁已移除"
                };
            }

            if (request.Command == "flush-dns")
            {
                await _executor.FlushDnsAsync();
                return new
                {
                    ok = true,
                    command = request.Command,
                    detail = "系统 DNS 解析缓存已刷新"
                };
            }

            if (request.Command == "disable-ipv6-adapters")
            {
                var adapterNames = (request.AdapterNames ?? Array.Empty<string>())
                    .Select(name => name?.Trim() ?? string.Empty)
                    .Where(IsSafeAdapterName)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                if (adapterNames.Length == 0)
                {
                    return new { ok = false, error = "未提供需要禁用 IPv6 绑定的网卡名称" };
                }

                await _executor.DisableIpv6AdaptersAsync(adapterNames);
                return new
                {
                    ok = true,
                    command = request.Command,
                    disabled = adapterNames.Length,
                    detail = $"已禁用 {adapterNames.Length} 个非 VPN 网卡的 IPv6 绑定：{string.Join("、", adapterNames)}"
                };
            }

            return new { ok = false, error = "未知命令" };
        }
        catch (Exception exception)
        {
            return new { ok = false, error = exception.GetType().Name + ": " + exception.Message };
        }
    }

    public static string HashPath(string path)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(path));
        return Convert.ToHexString(bytes)[..16];
    }

    public static bool IsSafeAdapterName(string name) =>
        !string.IsNullOrWhiteSpace(name) &&
        name.Length <= 256 &&
        !name.Any(char.IsControl);

    private static bool ConstantTimeEquals(string? a, string? b)
    {
        if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b))
        {
            return false;
        }

        var ab = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        return ab.Length == bb.Length && CryptographicOperations.FixedTimeEquals(ab, bb);
    }
}

internal sealed class WindowsHelperSystemExecutor : IHelperSystemExecutor
{
    [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
    private static extern bool DnsFlushResolverCache();

    public string CurrentUserSid => WindowsIdentity.GetCurrent().User?.Value ?? "unknown";
    public int CurrentProcessId => Environment.ProcessId;
    public string GetExpectedToken() => new PipeTokenStore().GetOrCreate();
    public IReadOnlyList<string> DiscoverClaudeExecutablePaths() => ClaudeInstallDiscovery.Discover().ExecutablePaths;
    public bool IsAllowedClaudePath(string path) => ClaudeInstallDiscovery.IsAllowedClaudeProgramPath(path);
    public IReadOnlyList<ProcessInfo> FindCurrentUserClaudeProcesses() => new WindowsProcessInspector().FindClaudeProcessTree();

    public async Task<string> ReadTimezoneAsync() =>
        (await RunProcessAsync("tzutil.exe", "/g")).Trim();

    public Task SetTimezoneAsync(string timezoneId) =>
        RunProcessAsync("tzutil.exe", "/s", timezoneId);

    public HelperFirewallStatus QueryFirewallGroupStatus(string groupName)
    {
        try
        {
            const string rulesSubKey = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
            using var key = Registry.LocalMachine.OpenSubKey(rulesSubKey, writable: false);
            if (key is null)
            {
                return new HelperFirewallStatus(false, 0, "无法打开 Windows 防火墙规则注册表键");
            }

            var count = 0;
            var groupMarker = $"EmbedCtxt={groupName}";
            var namePrefix = $"Name={groupName}.";
            foreach (var valueName in key.GetValueNames())
            {
                var raw = key.GetValue(valueName) as string;
                if (string.IsNullOrEmpty(raw))
                {
                    continue;
                }

                if ((raw.Contains(groupMarker, StringComparison.OrdinalIgnoreCase) ||
                     raw.Contains(namePrefix, StringComparison.OrdinalIgnoreCase)) &&
                    raw.Contains("Active=TRUE", StringComparison.OrdinalIgnoreCase))
                {
                    count++;
                }
            }

            var detail = count > 0
                ? $"防火墙组 {groupName} 当前有 {count} 条活动阻断规则"
                : $"防火墙控制就绪（组 {groupName} 当前无阻断规则）";
            return new HelperFirewallStatus(true, count, detail);
        }
        catch (Exception ex)
        {
            return new HelperFirewallStatus(false, 0, $"读取防火墙规则状态失败：{ex.Message}");
        }
    }

    public async Task ClearFirewallGroupAsync(string groupName)
    {
        var escapedGroupName = EscapePowerShellString(groupName);
        var script = string.Join(
            Environment.NewLine,
            "$ErrorActionPreference = 'Stop'",
            $"$rules = @(Get-NetFirewallRule -Group '{escapedGroupName}' -ErrorAction SilentlyContinue)",
            "if ($rules.Count -gt 0) {",
            "    $rules | Remove-NetFirewallRule -ErrorAction Stop",
            "}",
            "Write-Output ('removed=' + $rules.Count)");
        await RunPowerShellEncodedAsync(script);
    }

    public async Task ClearAllGuardianFirewallRulesAsync(string rulePrefix)
    {
        var escapedPrefix = EscapePowerShellString(rulePrefix);
        var script = string.Join(
            Environment.NewLine,
            "$ErrorActionPreference = 'Stop'",
            $"$rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {{ $_.Group -like '{escapedPrefix}*' -or $_.DisplayName -like '{escapedPrefix}*' }})",
            "if ($rules.Count -gt 0) {",
            "    $rules | Remove-NetFirewallRule -ErrorAction Stop",
            "}");
        await RunPowerShellEncodedAsync(script);
    }

    public Task AddFirewallBlockRuleAsync(string ruleName, string groupName, string programPath) =>
        RunProcessAsync(
            "netsh.exe",
            "advfirewall", "firewall", "add", "rule",
            $"name={ruleName}",
            $"group={groupName}",
            "dir=out",
            "action=block",
            "enable=yes",
            $"program={programPath}",
            "profile=any");

    public async Task<(int Terminated, int Remaining)> TerminateProcessesAsync(IReadOnlyList<int> processIds)
    {
        var terminated = 0;
        foreach (var pid in processIds.Distinct())
        {
            try
            {
                using var process = Process.GetProcessById(pid);
                process.Kill(true);
                terminated++;
            }
            catch
            {
            }
        }

        if (terminated > 0)
        {
            await Task.Delay(250);
        }

        var remaining = 0;
        var stillRunning = FindCurrentUserClaudeProcesses().Select(p => p.ProcessId).ToHashSet();
        foreach (var pid in processIds.Distinct())
        {
            if (stillRunning.Contains(pid))
            {
                remaining++;
            }
        }

        return (terminated, remaining);
    }

    public HelperWfpStatus QueryWfpDetailedSafe(string? adapterGuidText, bool allowLoopback)
    {
        try
        {
            return QueryWfpDetailed(adapterGuidText, allowLoopback);
        }
        catch (Exception ex)
        {
            return new HelperWfpStatus("unknown", $"无法读取 WFP 状态：{ex.Message}", 0);
        }
    }

    public HelperWfpStatus QueryWfpDetailed(string? adapterGuidText, bool allowLoopback)
    {
        var install = ClaudeInstallDiscovery.Discover();
        ulong luid = 0;
        if (TryParseAdapterGuid(adapterGuidText, out var guid))
        {
            try
            {
                luid = WfpNetworkPolicy.InterfaceLuid(guid);
            }
            catch
            {
                luid = 0;
            }
        }

        using var policy = new WfpNetworkPolicy();
        var state = policy.Status(
            install.PackageFamilyName,
            install.ExecutablePaths,
            luid,
            allowLoopback);
        var detail = state switch
        {
            "active" => $"WFP 内核出站锁生效中（覆盖 {install.ExecutablePaths.Count} 个程序" +
                        (allowLoopback ? "，允许回环" : "，严格 TUN-only") + "）",
            "stale" => "WFP 子层存在，但绑定的 TUN 网卡、Claude 版本或回环策略已过期（建议刷新 WFP）",
            _ => "WFP 内核出站锁未启用"
        };
        return new HelperWfpStatus(state, detail, install.ExecutablePaths.Count);
    }

    public async Task<HelperWfpEnableResult> EnableWfpAsync(
        string? adapterGuidText,
        IReadOnlyList<string> extraPaths,
        bool allowLoopback)
    {
        if (!TryParseAdapterGuid(adapterGuidText, out var adapterGuid))
        {
            return new HelperWfpEnableResult(false, "缺少有效的 VPN/TUN 网卡 GUID，无法绑定 WFP 策略", 0, 0, 0);
        }

        var luid = WfpNetworkPolicy.InterfaceLuid(adapterGuid);
        if (luid == 0)
        {
            return new HelperWfpEnableResult(false, "无法将 VPN/TUN 网卡 GUID 转换为接口 LUID", 0, 0, 0);
        }

        var install = ClaudeInstallDiscovery.Discover();
        var mergedPaths = install.ExecutablePaths
            .Concat(extraPaths)
            .Where(ClaudeInstallDiscovery.IsAllowedClaudeProgramPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (mergedPaths.Length == 0)
        {
            return new HelperWfpEnableResult(false, "未发现已安装的 Claude Desktop 可执行文件（EXE 或 MSIX），无法应用 WFP 出站锁", 0, 0, 0);
        }

        using var policy = new WfpNetworkPolicy();
        policy.Apply(install.PackageFamilyName, mergedPaths, luid, allowLoopback);

        // Close pre-existing current-user Claude Desktop processes and verify exit so old sockets cannot bypass ALE_AUTH_CONNECT
        var existingPids = FindCurrentUserClaudeProcesses().Select(p => p.ProcessId).ToArray();
        var (terminated, remaining) = existingPids.Length > 0
            ? await TerminateProcessesAsync(existingPids)
            : (0, 0);

        var modeDesc = allowLoopback ? "TUN-only + 允许回环" : "严格 TUN-only";
        var pkgSuffix = string.IsNullOrWhiteSpace(install.PackageFamilyName) ? "）" : $" + MSIX {install.PackageFamilyName}）";
        var killSuffix = terminated > 0
            ? remaining > 0
                ? $"；已尝试关闭 {terminated} 个旧 Claude 进程，但仍有 {remaining} 个残留，请手动退出旧实例"
                : $"；已关闭 {terminated} 个旧 Claude 进程并确认退出"
            : string.Empty;
        return new HelperWfpEnableResult(
            true,
            $"WFP 内核出站锁已启用（{modeDesc}，覆盖 {mergedPaths.Length} 个可执行文件{pkgSuffix}{killSuffix}",
            mergedPaths.Length,
            terminated,
            remaining);
    }

    public void DisableWfp()
    {
        using var policy = new WfpNetworkPolicy();
        policy.Remove();
    }

    public async Task FlushDnsAsync()
    {
        var flushed = false;
        try
        {
            flushed = DnsFlushResolverCache();
        }
        catch
        {
        }

        if (!flushed)
        {
            await RunProcessAsync("ipconfig.exe", "/flushdns");
        }
    }

    public async Task DisableIpv6AdaptersAsync(IReadOnlyList<string> adapterNames)
    {
        var lines = new List<string> { "$ErrorActionPreference = 'Stop'" };
        foreach (var name in adapterNames)
        {
            var escaped = EscapePowerShellString(name);
            lines.Add($"Disable-NetAdapterBinding -Name '{escaped}' -ComponentID ms_tcpip6 -ErrorAction Stop");
        }

        await RunPowerShellEncodedAsync(string.Join(Environment.NewLine, lines));
    }

    private static bool TryParseAdapterGuid(string? raw, out Guid guid)
    {
        guid = Guid.Empty;
        return !string.IsNullOrWhiteSpace(raw) && Guid.TryParse(raw.Trim(), out guid) && guid != Guid.Empty;
    }

    private static Task<string> RunPowerShellEncodedAsync(string script) =>
        RunProcessAsync(
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));

    private static string EscapePowerShellString(string value) =>
        value.Replace("'", "''", StringComparison.Ordinal);

    private static async Task<string> RunProcessAsync(string fileName, params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo);
        if (process is null)
        {
            throw new InvalidOperationException($"无法启动 {fileName}");
        }

        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        var output = await outputTask;
        var error = await errorTask;
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                ProcessDiagnostics.FormatFailure(fileName, process.ExitCode, output, error));
        }

        return output;
    }
}
