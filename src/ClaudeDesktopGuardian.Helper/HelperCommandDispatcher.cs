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
    string Detail,
    bool? PolicyEffective = null);

internal sealed record HelperTcpOnlyStatus(string State, string Detail, int RuleCount = 0);

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
    Task AddFirewallPackageBlockRuleAsync(string groupName) => Task.CompletedTask;
    Task<(int Terminated, int Remaining)> TerminateProcessesAsync(IReadOnlyList<int> processIds);
    HelperWfpStatus QueryWfpDetailedSafe(string? adapterGuid, bool allowLoopback);
    HelperWfpStatus QueryWfpDetailed(string? adapterGuid, bool allowLoopback);
    Task<HelperWfpEnableResult> EnableWfpAsync(string? adapterGuid, IReadOnlyList<string> extraPaths, bool allowLoopback);
    void DisableWfp();
    Task FlushDnsAsync();
    Task DisableIpv6AdaptersAsync(IReadOnlyList<string> adapterNames);
    HelperTcpOnlyStatus QueryTcpOnlyStatus(string groupName);
    Task<HelperTcpOnlyStatus> EnableTcpOnlyAsync(string groupName);
    Task DisableTcpOnlyAsync(string groupName);
}

internal sealed class HelperCommandDispatcher
{
    public const string RulePrefix = "ClaudeDesktopGuardian.";

    private readonly IHelperSystemExecutor _executor;
    private readonly SemaphoreSlim _mutationLock = new(1, 1);
    private int _tcpOnlyRefreshPending = 1;

    private HelperTcpOnlyStatus TcpOnlyStatus(string group)
    {
        var status = _executor.QueryTcpOnlyStatus(group);
        return status.State == "active" && Volatile.Read(ref _tcpOnlyRefreshPending) != 0
            ? status with { State = "stale", Detail = "助手重启或刷新尚未完成，需要重新应用并验证旧会话退出" } : status;
    }

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
                    "tcp-only-enable" or
                    "tcp-only-status" or
                    "tcp-only-disable" or
                    "flush-dns" or
                    "disable-ipv6-adapters"))
            {
                return new { ok = false, error = "未知命令或认证失败" };
            }

            var sid = string.IsNullOrWhiteSpace(_executor.CurrentUserSid) ? "unknown" : _executor.CurrentUserSid;
            var groupName = RulePrefix + sid.Replace('\\', '_');

            // Read-only commands execute immediately without waiting behind slow mutating commands
            if (request.Command == "status")
            {
                var wfp = _executor.QueryWfpDetailedSafe(request.AdapterGuid, request.AllowLoopback);
                var fw = _executor.QueryFirewallGroupStatus(groupName);
                var tcpOnly = TcpOnlyStatus(groupName + ".TcpOnly");
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
                    firewallPolicyEffective = fw.PolicyEffective,
                    tcpOnlyState = tcpOnly.State,
                    tcpOnlyDetail = tcpOnly.Detail,
                    helperDetail = $"受限命名管道在线（PID={_executor.CurrentProcessId}，组={groupName}）"
                };
            }

            if (request.Command == "tcp-only-status")
            {
                var status = TcpOnlyStatus(groupName + ".TcpOnly");
                return new { ok = true, tcpOnlyState = status.State, tcpOnlyDetail = status.Detail, detail = status.Detail };
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

            // Mutating commands are serialized to prevent concurrent firewall/WFP/timezone races
            await _mutationLock.WaitAsync();
            try
            {
                if (request.Command == "tcp-only-enable")
                {
                    Interlocked.Exchange(ref _tcpOnlyRefreshPending, 1);
                    var existing = _executor.FindCurrentUserClaudeProcesses()
                        .Where(process => string.IsNullOrEmpty(process.UserSid) ||
                                          string.Equals(process.UserSid, sid, StringComparison.OrdinalIgnoreCase))
                        .Select(process => process.ProcessId).ToArray();
                    var (_, oldRemaining) = await _executor.TerminateProcessesAsync(existing);
                    if (oldRemaining > 0)
                        return new { ok = false, error = "既有 Claude 会话未退出，TCP-only 刷新已中止", tcpOnlyState = "stale" };
                    var status = await _executor.EnableTcpOnlyAsync(groupName + ".TcpOnly");
                    var pids = _executor.FindCurrentUserClaudeProcesses()
                        .Where(process => string.IsNullOrEmpty(process.UserSid) ||
                                          string.Equals(process.UserSid, sid, StringComparison.OrdinalIgnoreCase))
                        .Select(process => process.ProcessId).ToArray();
                    var (_, remaining) = status.State == "active"
                        ? await _executor.TerminateProcessesAsync(pids) : (0, 0);
                    var after = _executor.QueryTcpOnlyStatus(groupName + ".TcpOnly");
                    var succeeded = status.State == "active" && after.State == "active" && remaining == 0;
                    if (succeeded)
                        Interlocked.Exchange(ref _tcpOnlyRefreshPending, 0);
                    return new
                    {
                        ok = succeeded,
                        tcpOnlyState = remaining > 0 ? "stale" : after.State,
                        tcpOnlyDetail = after.Detail,
                        error = succeeded ? "" : remaining > 0 ? "既有 Claude 会话未退出，拒绝宣称 TCP-only 已完成" : after.Detail,
                        detail = after.Detail
                    };
                }
                if (request.Command == "tcp-only-disable")
                {
                    await _executor.DisableTcpOnlyAsync(groupName + ".TcpOnly");
                    var after = _executor.QueryTcpOnlyStatus(groupName + ".TcpOnly");
                    var disabled = after.State == "off";
                    return new
                    {
                        ok = disabled,
                        tcpOnlyState = after.State,
                        tcpOnlyDetail = after.Detail,
                        detail = after.Detail,
                        error = disabled ? "" : "TCP-only 托管规则未能清理"
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

                    // Idempotent clear before re-adding so repeated triggers never pile up duplicate rules
                    await _executor.ClearFirewallGroupAsync(groupName);
                    foreach (var path in allBlockPaths)
                    {
                        var ruleName = groupName + "." + HashPath(path);
                        await _executor.AddFirewallBlockRuleAsync(ruleName, groupName, path);
                    }
                    await _executor.AddFirewallPackageBlockRuleAsync(groupName);

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
            finally
            {
                _mutationLock.Release();
            }
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

internal sealed partial class WindowsHelperSystemExecutor : IHelperSystemExecutor
{
    [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
    private static extern bool DnsFlushResolverCache();

    public string CurrentUserSid => WindowsIdentity.GetCurrent().User?.Value ?? "unknown";
    public int CurrentProcessId => Environment.ProcessId;
    public string GetExpectedToken() => new PipeTokenStore().GetOrCreate();
    public IReadOnlyList<string> DiscoverClaudeExecutablePaths() => ClaudeInstallDiscovery.Discover(forceRefresh: true).ExecutablePaths;
    public bool IsAllowedClaudePath(string path) => ClaudeInstallDiscovery.IsAllowedClaudeProgramPath(path);
    public IReadOnlyList<ProcessInfo> FindCurrentUserClaudeProcesses() => new WindowsProcessInspector().FindClaudeProcessTree();

    public Task<string> ReadTimezoneAsync()
    {
        TimeZoneInfo.ClearCachedData();
        return Task.FromResult(TimeZoneInfo.Local.Id);
    }

    public Task SetTimezoneAsync(string timezoneId) =>
        RunProcessAsync("tzutil.exe", "/s", timezoneId);

    public HelperFirewallStatus QueryFirewallGroupStatus(string groupName)
    {
        var evidence = _firewall.Read(groupName);
        return new(evidence.Readable, evidence.Rules.Count(rule => rule.Enabled), evidence.Detail, evidence.Effective);
    }

    public Task ClearFirewallGroupAsync(string groupName)
    {
        var policy = _firewall.Read(groupName);
        if (!policy.Readable) throw new InvalidOperationException(policy.Detail);
        foreach (var rule in policy.Rules.Where(rule => IsManagedBlockRule(rule.Name, groupName)))
            _firewall.Remove(rule.Name);
        return Task.CompletedTask;
    }

    public async Task ClearAllGuardianFirewallRulesAsync(string rulePrefix)
    {
        var group = rulePrefix + CurrentUserSid.Replace('\\', '_');
        await ClearFirewallGroupAsync(group);
        await DisableTcpOnlyAsync(group + ".TcpOnly");
    }

    public Task AddFirewallBlockRuleAsync(string ruleName, string groupName, string programPath)
    {
        _firewall.Add(new FirewallRuleEvidence(
            ruleName, groupName, programPath, "", true, 2, 0, 256, 7, "", "", "*", "*", "All", false, "",
            $"O:LSD:(A;;CC;;;{CurrentUserSid})"));
        return Task.CompletedTask;
    }

    public Task AddFirewallPackageBlockRuleAsync(string groupName)
    {
        var install = _discoverTcpOnly();
        if (string.IsNullOrWhiteSpace(install.PackageFamilyName)) return Task.CompletedTask;
        Marshal.ThrowExceptionForHR(DeriveAppContainerSidFromAppContainerName(install.PackageFamilyName, out var pointer));
        string packageSid;
        try { packageSid = new SecurityIdentifier(pointer).Value; }
        finally { FreeSid(pointer); }
        var ruleName = groupName + "." + HelperCommandDispatcher.HashPath("|" + packageSid);
        _firewall.Add(new FirewallRuleEvidence(
            ruleName, groupName, "", packageSid, true, 2, 0, 256, 7, "", "", "*", "*", "All", false, "",
            $"O:LSD:(A;;CC;;;{CurrentUserSid})"));
        return Task.CompletedTask;
    }

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

        var install = ClaudeInstallDiscovery.Discover(forceRefresh: true);
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

    private static Task<string> RunProcessAsync(string fileName, params string[] arguments) =>
        RunProcessWithTimeoutAsync(fileName, 15_000, arguments);

    internal static async Task<string> RunProcessWithTimeoutAsync(
        string fileName,
        int timeoutMs,
        params string[] arguments)
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
        using var cts = new CancellationTokenSource(Math.Max(100, timeoutMs));
        try
        {
            await process.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"{fileName} 执行超时（>{timeoutMs} ms），已强制终止子进程");
        }

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
