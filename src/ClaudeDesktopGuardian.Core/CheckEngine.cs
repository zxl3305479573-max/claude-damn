using System.Net;

namespace ClaudeDesktopGuardian.Core;

public enum ProtectionAction
{
    None,
    ApplyBlockAndTerminate,
    EnforceExistingBlockTerminateOnly,
    ClearBlock,
    StayBlocked
}

public sealed record ProtectionDecision(
    ProtectionAction Action,
    string TripReason,
    IReadOnlyList<CheckResult> BlockingFailures);

/// <summary>
/// Pure, testable Fail-Closed protection state machine.
/// Never auto-clears a block when Claude exits or on a lightweight tick;
/// recovery requires an explicit full-check pass (allowClearBlock=true).
/// </summary>
public static class ProtectionPolicyEvaluator
{
    public static IReadOnlyList<CheckResult> GetEffectiveBlockingFailures(
        GuardianReport report,
        bool ignoreWebRtc = false) =>
        report.BlockingFailures
            .Where(check =>
                check.Id != GuardianCheckIds.WebRtc ||
                check.Status == CheckStatus.Fail)
            .ToArray();

    public static bool HasEffectiveUiStatus(
        GuardianReport report,
        CheckStatus status,
        bool ignoreWebRtc) =>
        report.Checks.Any(check =>
            check.Blocking &&
            check.Status == status &&
            !(ignoreWebRtc &&
              check.Id == GuardianCheckIds.WebRtc &&
              check.Status == CheckStatus.Unknown));

    public static string FormatTripReason(IReadOnlyList<CheckResult> failures) =>
        string.Join(
            "；",
            failures.Select(check =>
                $"{check.Title}（{check.Status}）：{check.Detail}"));

    public static ProtectionDecision Evaluate(
        GuardianReport report,
        bool currentlyBlocked,
        bool ignoreWebRtc,
        bool allowClearBlock = false)
    {
        var failures = GetEffectiveBlockingFailures(report, ignoreWebRtc);
        var reason = FormatTripReason(failures);
        var hasClaude = report.ProtectedProcesses.Count > 0;

        if (!currentlyBlocked)
        {
            return failures.Count > 0 && hasClaude
                ? new ProtectionDecision(ProtectionAction.ApplyBlockAndTerminate, reason, failures)
                : new ProtectionDecision(ProtectionAction.None, reason, failures);
        }

        if (failures.Count > 0 && hasClaude)
        {
            return new ProtectionDecision(ProtectionAction.EnforceExistingBlockTerminateOnly, reason, failures);
        }

        if (allowClearBlock && failures.Count == 0)
        {
            return new ProtectionDecision(ProtectionAction.ClearBlock, string.Empty, failures);
        }

        return new ProtectionDecision(ProtectionAction.StayBlocked, reason, failures);
    }

    public static bool ShouldAutoRefreshStaleWfp(GuardianConfig config, GuardianReport report) =>
        config.WfpStrictEnabled &&
        report.Network.HelperAlive &&
        !report.Network.ProxyPathSkipped &&
        !string.IsNullOrWhiteSpace(report.Network.AdapterGuid) &&
        string.Equals(report.Network.WfpPolicyState, "stale", StringComparison.OrdinalIgnoreCase) &&
        report.ProtectedProcesses.Count == 0;

    public static (bool RefreshWfp, bool RefreshTcpOnly) NeedsRecoveryPolicyRefresh(
        GuardianConfig config,
        GuardianReport report)
    {
        if (!report.Network.HelperAlive || report.Network.ProxyPathSkipped)
        {
            return (false, false);
        }

        var refreshWfp = config.WfpStrictEnabled &&
                         !string.IsNullOrWhiteSpace(report.Network.AdapterGuid) &&
                         (string.Equals(report.Network.WfpPolicyState, "stale", StringComparison.OrdinalIgnoreCase) ||
                          string.Equals(report.Network.WfpPolicyState, "off", StringComparison.OrdinalIgnoreCase));
        var refreshTcpOnly = config.TcpOnlyEnabled &&
                             (string.Equals(report.Network.TcpOnlyState, "stale", StringComparison.OrdinalIgnoreCase) ||
                              string.Equals(report.Network.TcpOnlyState, "off", StringComparison.OrdinalIgnoreCase));
        return (refreshWfp, refreshTcpOnly);
    }

    public static LaunchGateDecision EvaluateLaunchGate(
        GuardianReport? report,
        bool currentlyBlocked,
        bool ignoreWebRtc)
    {
        if (currentlyBlocked)
        {
            return new LaunchGateDecision(
                false,
                "当前处于防火墙阻断锁定中，请先点击「检查并解除阻断」确认恢复后再启动 Claude",
                report is null ? Array.Empty<CheckResult>() : GetEffectiveBlockingFailures(report, ignoreWebRtc));
        }

        if (report is null)
        {
            return new LaunchGateDecision(
                false,
                "尚未完成环境检查，请先执行完整检查后再启动 Claude",
                Array.Empty<CheckResult>());
        }

        if (report.Network.ProxyPathSkipped)
        {
            var skippedFailures = GetEffectiveBlockingFailures(report, ignoreWebRtc);
            return new LaunchGateDecision(
                false,
                "代理客户端或 VPN/TUN 网卡未就绪，已拒绝启动 Claude 以防直连暴露",
                skippedFailures);
        }

        var failures = GetEffectiveBlockingFailures(report, ignoreWebRtc);
        if (failures.Count > 0)
        {
            return new LaunchGateDecision(
                false,
                FormatTripReason(failures),
                failures);
        }

        return new LaunchGateDecision(
            true,
            "环境安全检查全部通过，允许启动 Claude Desktop",
            Array.Empty<CheckResult>());
    }
}

public sealed class GuardianCheckEngine
{
    private readonly IEnvironmentProbe _probe;
    private readonly IProcessInspector _processInspector;
    private readonly IWebRtcBrowserProbe? _browserProbe;
    private readonly IGuardianClock _clock;
    private string _lastExitIp = string.Empty;
    private WebRtcBrowserResult? _lastBrowserWebRtc;
    private bool _hasCompletedFullCheck;

    public GuardianCheckEngine(
        IEnvironmentProbe probe,
        IProcessInspector processInspector,
        IGuardianClock? clock = null)
        : this(probe, processInspector, null, clock)
    {
    }

    public GuardianCheckEngine(
        IEnvironmentProbe probe,
        IProcessInspector processInspector,
        IWebRtcBrowserProbe? browserProbe,
        IGuardianClock? clock = null)
    {
        _probe = probe;
        _processInspector = processInspector;
        _browserProbe = browserProbe;
        _clock = clock ?? new SystemGuardianClock();
    }

    public async Task<GuardianReport> RunAsync(
        GuardianConfig config,
        bool full,
        CancellationToken cancellationToken)
    {
        var processes = await Task.Run(_processInspector.FindClaudeProcessTree, cancellationToken);
        var network = await Task.Run(
            () => _probe.CaptureNetworkAsync(config, processes, full, cancellationToken), cancellationToken);

        if (network.ContextChanged) _lastBrowserWebRtc = null;
        var runBrowserWebRtc = (full || network.ContextChanged) &&
                               _browserProbe is not null &&
                               !network.ProxyPathSkipped &&
                               CanProbeBrowser(network) &&
                               !config.IsCheckDisabled(GuardianCheckIds.WebRtc);
        if (runBrowserWebRtc)
        {
            var browserWebRtc = await _browserProbe!.ProbeAsync(
                config.EffectiveStunUrls,
                cancellationToken);
            _lastBrowserWebRtc = browserWebRtc;
            network = network with { BrowserWebRtc = browserWebRtc };
        }
        else if (!full && !network.ContextChanged && _lastBrowserWebRtc is not null && !network.ProxyPathSkipped && CanProbeBrowser(network))
        {
            network = network with { BrowserWebRtc = _lastBrowserWebRtc };
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (full || network.ContextChanged)
        {
            _hasCompletedFullCheck = true;
        }

        var includeFullChecks = full || network.ContextChanged || _hasCompletedFullCheck;
        var checks = EvaluateAllChecks(config, network, processes, includeFullChecks);
        return new GuardianReport(_clock.UtcNow, checks, network, processes);
    }

    /// <summary>
    /// Re-runs only the targeted check item (and its minimal dependency) and merges the updated
    /// check result into the previous report without running unrelated external probes.
    /// </summary>
    public async Task<GuardianReport> RunSingleCheckAsync(
        GuardianReport previousReport,
        string checkId,
        GuardianConfig config,
        CancellationToken cancellationToken)
    {
        var processes = await Task.Run(_processInspector.FindClaudeProcessTree, cancellationToken);
        NetworkSnapshot network;
        if (_probe is ISingleCheckProbe singleProbe)
        {
            network = await Task.Run(() => singleProbe.CaptureSingleCheckAsync(
                previousReport.Network,
                checkId,
                config,
                processes,
                cancellationToken), cancellationToken);
        }
        else
        {
            network = await Task.Run(
                () => _probe.CaptureNetworkAsync(config, processes, full: true, cancellationToken), cancellationToken);
        }

        if (network.ContextChanged) _lastBrowserWebRtc = null;
        if ((network.ContextChanged || string.Equals(checkId, GuardianCheckIds.WebRtc, StringComparison.OrdinalIgnoreCase)) &&
            _browserProbe is not null &&
            !network.ProxyPathSkipped &&
            CanProbeBrowser(network) &&
            !config.IsCheckDisabled(GuardianCheckIds.WebRtc))
        {
            var browserWebRtc = await _browserProbe.ProbeAsync(
                config.EffectiveStunUrls,
                cancellationToken);
            _lastBrowserWebRtc = browserWebRtc;
            network = network with { BrowserWebRtc = browserWebRtc };
        }
        else if (!network.ContextChanged && CanProbeBrowser(network) && previousReport.Network.BrowserWebRtc is not null && network.BrowserWebRtc is null)
        {
            network = network with { BrowserWebRtc = previousReport.Network.BrowserWebRtc };
        }

        var evaluated = EvaluateAllChecks(config, network, processes, includeFullChecks: true);
        cancellationToken.ThrowIfCancellationRequested();
        return new GuardianReport(_clock.UtcNow, evaluated, network, processes);
    }

    private List<CheckResult> EvaluateAllChecks(
        GuardianConfig config,
        NetworkSnapshot network,
        IReadOnlyList<ProcessInfo> processes,
        bool includeFullChecks)
    {
        var checks = new List<CheckResult>();

        // 1. Claude process tree (advisory)
        checks.Add(Result(
            GuardianCheckIds.ClaudeProcess,
            "Claude 进程树",
            processes.Count > 0 ? CheckStatus.Ok : CheckStatus.Warn,
            blocking: false,
            processes.Count > 0 ? $"已识别 {processes.Count} 个进程" : "当前没有识别到 Claude Desktop 进程"));

        // 2. Proxy Client (critical)
        var proxyTitle = string.IsNullOrWhiteSpace(network.ProxyClientName)
            ? ProxyClientModes.DisplayName(config.ProxyClientMode)
            : network.ProxyClientName;
        checks.Add(Result(
            GuardianCheckIds.ProxyClient,
            "代理客户端",
            network.ProxyClientAlive ? CheckStatus.Ok : CheckStatus.Fail,
            blocking: true,
            string.IsNullOrWhiteSpace(network.ProxyClientDetail)
                ? network.ProxyClientAlive ? $"{proxyTitle} 运行中" : $"{proxyTitle} 未运行"
                : network.ProxyClientDetail));

        // 3. VPN/TUN Adapter (critical)
        checks.Add(Result(
            GuardianCheckIds.VpnAdapter,
            "VPN/TUN 网卡",
            string.IsNullOrWhiteSpace(network.AdapterName) ? CheckStatus.Fail : CheckStatus.Ok,
            blocking: true,
            string.IsNullOrWhiteSpace(network.AdapterName)
                ? string.IsNullOrWhiteSpace(network.AdapterDiagnostic)
                    ? "没有识别到在线 VPN/TUN 网卡"
                    : network.AdapterDiagnostic
                : $"{network.AdapterName} / {network.AdapterDescription}" +
                  (network.AdapterIsFakeIp ? "（198.18 Fake-IP）" : string.Empty)));

        // 4. Default Route (critical)
        var routes = network.DestinationRoutes ?? Array.Empty<DestinationRoute>();
        var routeStatus = string.IsNullOrWhiteSpace(network.AdapterName) || routes.Any(route => route.Succeeded && !route.Matches)
            ? CheckStatus.Fail
            : Collected(network, GuardianCheckIds.DefaultRoute) && routes.Count > 0 && routes.All(route => route.Matches)
                ? CheckStatus.Ok : CheckStatus.Unknown;
        checks.Add(Result(
            GuardianCheckIds.DefaultRoute,
            "目标最佳路由",
            routeStatus,
            blocking: true,
            routeStatus == CheckStatus.Ok
                ? "已查询具体目标最佳路由，均经当前 TUN（含拆分默认路由与更具体路由）"
                : routeStatus == CheckStatus.Fail ? "TUN 未在线或存在具体目标经其他接口出站"
                    : "具体目标最佳路由采集失败或尚未验证"));

        // 5. Egress IP (critical, including System Proxy vs TUN divergence detection)
        checks.Add(EvaluateEgressIp(config, network));

        // 6. IP Consistency + 48h drift (optional)
        checks.Add(EvaluateIpConsistency(config, network));

        // 7. Timezone consistency (optional)
        checks.Add(EvaluateTimezone(config, network));

        // 8. System Locale (optional)
        checks.Add(EvaluateLocale(config, network));

        // 9. DNS Tunnel verification (optional, blocking when enabled & failing unless downgraded)
        checks.Add(EvaluateDns(config, network));

        // 10. IPv6 Egress + Active Route Table (critical)
        checks.Add(EvaluateIpv6(config, network));

        // 11. WebRTC Dual-Layer Leak Check (confirmed leak NEVER downgraded when enabled)
        checks.Add(EvaluateWebRtc(config, network));

        // 12. Active Connections Policy Check (Claude process TCP connections)
        checks.Add(EvaluateActiveConnections(config, network));

        // 13. Privileged Helper Service Check
        checks.Add(EvaluateHelperService(network));

        // 14. WFP Kernel Outbound Lock (critical when WfpStrictEnabled=true; advisory otherwise)
        checks.Add(EvaluateWfpPolicy(config, network));

        // 15. Firewall Readiness (real helper + firewall rule state)
        checks.Add(EvaluateFirewallReadiness(network));
        checks.Add(EvaluateTcpOnly(config, network));

        if (includeFullChecks)
        {
            // 16. Clash Pinned Rules (optional)
            checks.Add(EvaluateClashRules(config, network));

            // 17. Claude Client Language (optional)
            checks.Add(EvaluateClientLanguage(config, network));

            // 18. ASN Network Type (optional)
            checks.Add(EvaluateAsn(config, network));

            // 19. Claude HTTPS Ecosystem Reachability (optional, blocking when enabled)
            checks.Add(EvaluateClaudeDomains(config, network));

            // 20-23. Pluggable 4-Part IP Reputation (optional)
            checks.AddRange(EvaluateIpReputation(config, network));
        }

        return AttachEvidence(checks, config, network, processes);
    }

    private static CheckResult EvaluateEgressIp(GuardianConfig config, NetworkSnapshot network)
    {
        if (network.ProxyPathSkipped)
        {
            return Result(
                GuardianCheckIds.EgressIp,
                "出口 IP",
                CheckStatus.Fail,
                blocking: true,
                "代理路径失效，已跳过外网探测（避免真实 IP 直连暴露）");
        }

        if (string.IsNullOrWhiteSpace(network.ExitIp))
        {
            var detail = string.IsNullOrWhiteSpace(network.Ipv4ProbeDetail)
                ? "无法取得当前出口 IP"
                : $"无法取得当前出口 IP（{network.Ipv4ProbeDetail}）";
            return Result(GuardianCheckIds.EgressIp, "出口 IP", CheckStatus.Unknown, blocking: true, detail);
        }

        var sourceSuffix = string.IsNullOrWhiteSpace(network.ExitIpSource) ? string.Empty : $"（源：{network.ExitIpSource}）";
        if (!IsExpectedExit(network, config))
        {
            return Result(
                GuardianCheckIds.EgressIp,
                "出口 IP",
                CheckStatus.Fail,
                blocking: true,
                $"当前出口 {network.ExitIp}，国家 {network.ExitCountry}{sourceSuffix}，不符合目标出口策略");
        }

        if (network.SystemProxyConfigured)
        {
            if (string.IsNullOrWhiteSpace(network.TunDirectExitIp))
            {
                var tunErr = string.IsNullOrWhiteSpace(network.TunDirectProbeDetail)
                    ? "未返回有效地址"
                    : network.TunDirectProbeDetail;
                return Result(
                    GuardianCheckIds.EgressIp,
                    "出口 IP",
                    CheckStatus.Unknown,
                    blocking: true,
                    $"系统代理({network.SystemProxyUri})出口={network.ExitIp}({network.ExitCountry})，但绕过代理的 TUN 路径未取得出口（{tunErr}）");
            }

            if ((string.Equals(network.TunDirectExitCountry, "CN", StringComparison.OrdinalIgnoreCase) &&
                 !string.Equals(config.ExpectedExitCountry, "CN", StringComparison.OrdinalIgnoreCase)) ||
                !string.Equals(network.TunDirectExitCountry, network.ExitCountry, StringComparison.OrdinalIgnoreCase))
            {
                return Result(
                    GuardianCheckIds.EgressIp,
                    "出口 IP",
                    CheckStatus.Fail,
                    blocking: true,
                    $"系统代理与 TUN 路径出口国家不一致：系统代理={network.ExitIp}({network.ExitCountry})，TUN 直连={network.TunDirectExitIp}({network.TunDirectExitCountry})");
            }

            if (!string.Equals(network.TunDirectExitIp, network.ExitIp, StringComparison.OrdinalIgnoreCase))
            {
                return Result(
                    GuardianCheckIds.EgressIp,
                    "出口 IP",
                    CheckStatus.Unknown,
                    blocking: true,
                    $"系统代理与 TUN 路径出口 IP 不一致：系统代理={network.ExitIp}({network.ExitCountry})，TUN 直连={network.TunDirectExitIp}({network.TunDirectExitCountry})");
            }

            return Result(
                GuardianCheckIds.EgressIp,
                "出口 IP",
                CheckStatus.Ok,
                blocking: true,
                $"当前出口 {network.ExitIp}，国家 {network.ExitCountry}{sourceSuffix}（系统代理与 TUN 路径一致）");
        }

        return Result(
            GuardianCheckIds.EgressIp,
            "出口 IP",
            CheckStatus.Ok,
            blocking: true,
            $"当前出口 {network.ExitIp}，国家 {network.ExitCountry}{sourceSuffix}");
    }

    private static CheckResult EvaluateActiveConnections(GuardianConfig config, NetworkSnapshot network)
    {
        if (!Collected(network, GuardianCheckIds.ActiveConnections))
            return Result(GuardianCheckIds.ActiveConnections, "活动连接", CheckStatus.Unknown, true,
                "连接/UDP 端点采集失败或尚未完成，不能把空列表视为无连接");
        if (network.ActiveConnections.Count == 0)
        {
            return Result(
                GuardianCheckIds.ActiveConnections,
                "活动连接",
                CheckStatus.Ok,
                blocking: false,
                $"当前无受保护进程的已建立 TCP 连接；UDP 绑定端点 {network.UdpEndpoints?.Count ?? 0} 个（不证明已经发送）");
        }

        var unexpected = new List<string>();
        foreach (var raw in network.ActiveConnections)
        {
            var endpoint = raw.Trim();
            var spaceIndex = endpoint.LastIndexOf(' ');
            if (spaceIndex >= 0 && spaceIndex + 1 < endpoint.Length)
            {
                endpoint = endpoint[(spaceIndex + 1)..];
            }

            if (!TrySplitEndpoint(endpoint, out var host, out var port))
            {
                return Result(GuardianCheckIds.ActiveConnections, "活动连接", CheckStatus.Unknown, true, "连接端点格式无效");
            }

            if (IsLoopbackHost(host) || port == 443)
            {
                continue;
            }

            unexpected.Add(endpoint);
        }

        if (unexpected.Count > 0)
        {
            return Result(
                GuardianCheckIds.ActiveConnections,
                "活动连接",
                CheckStatus.Warn,
                blocking: config.BlockOnWarning,
                $"发现 {unexpected.Count} 条非 TCP 443/回环连接：{string.Join("、", unexpected.Take(6))}");
        }

        return Result(
            GuardianCheckIds.ActiveConnections,
            "活动连接",
            CheckStatus.Ok,
            blocking: false,
            $"已检查 {network.ActiveConnections.Count} 条连接，均符合 TCP 443 或本机回环");
    }

    private static CheckResult EvaluateHelperService(NetworkSnapshot network)
    {
        if (!network.HelperAlive)
        {
            return Result(
                GuardianCheckIds.HelperService,
                "管理员助手",
                CheckStatus.Fail,
                blocking: true,
                string.IsNullOrWhiteSpace(network.HelperDetail)
                    ? "管理员助手命名管道不可达，无法执行防火墙急停、WFP 策略或时区切换"
                    : network.HelperDetail);
        }

        return Result(
            GuardianCheckIds.HelperService,
            "管理员助手",
            CheckStatus.Ok,
            blocking: false,
            string.IsNullOrWhiteSpace(network.HelperDetail)
                ? "受限命名管道在线，可执行提权防护操作"
                : network.HelperDetail);
    }

    private static CheckResult EvaluateFirewallReadiness(NetworkSnapshot network)
    {
        if (!network.HelperAlive)
        {
            return Result(
                GuardianCheckIds.FirewallReadiness,
                "防火墙保护",
                CheckStatus.Fail,
                blocking: true,
                "管理员助手离线，无法核验或下发本程序防火墙规则");
        }

        if (!network.FirewallApiOk)
        {
            return Result(
                GuardianCheckIds.FirewallReadiness,
                "防火墙保护",
                CheckStatus.Fail,
                blocking: true,
                string.IsNullOrWhiteSpace(network.FirewallDetail)
                    ? "无法读取 Windows 防火墙规则状态"
                    : network.FirewallDetail);
        }

        if (network.FirewallPolicyEffective != true)
            return Result(GuardianCheckIds.FirewallReadiness, "防火墙保护",
                network.FirewallPolicyEffective == false ? CheckStatus.Fail : CheckStatus.Unknown, true,
                "防火墙服务、活动配置或本地策略未生效/无法核验；" + network.FirewallDetail);

        var detail = !string.IsNullOrWhiteSpace(network.FirewallDetail)
            ? network.FirewallDetail
            : network.FirewallActiveRuleCount > 0
                ? $"当前存在 {network.FirewallActiveRuleCount} 条 Guardian 阻断规则（兼容 EXE 与 MSIX）"
                : "防火墙控制就绪，当前无残留阻断规则";
        return Result(
            GuardianCheckIds.FirewallReadiness,
            "防火墙保护",
            CheckStatus.Ok,
            blocking: false,
            detail);
    }

    private static CheckResult EvaluateTcpOnly(GuardianConfig config, NetworkSnapshot network)
    {
        if (!config.TcpOnlyEnabled)
            return Result(GuardianCheckIds.TcpOnlyPolicy, "Claude TCP-only", CheckStatus.Skip, false, "独立出站 UDP 阻断未启用（默认关闭）");
        var status = network.TcpOnlyState switch
        {
            "active" when network.FirewallPolicyEffective == true => CheckStatus.Ok,
            "off" or "stale" or "invalid" => CheckStatus.Fail,
            _ => CheckStatus.Unknown
        };
        return Result(GuardianCheckIds.TcpOnlyPolicy, "Claude TCP-only", status, true,
            string.IsNullOrWhiteSpace(network.TcpOnlyDetail) ? "未取得完整 TCP-only 生效证据，需要新版管理员助手" : network.TcpOnlyDetail);
    }

    private static bool Collected(NetworkSnapshot network, string id) =>
        network.Observations?.TryGetValue(id, out var observation) == true && observation.Succeeded;

    private static bool CanProbeBrowser(NetworkSnapshot network) => Collected(network, GuardianCheckIds.DefaultRoute) &&
        network.DestinationRoutes is { Count: > 0 } && network.DestinationRoutes.All(route => route.Matches);

    private static bool TrySplitEndpoint(string endpoint, out string host, out int port)
    {
        host = string.Empty;
        port = 0;
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            return false;
        }

        var colon = endpoint.LastIndexOf(':');
        if (colon <= 0 || colon >= endpoint.Length - 1)
        {
            return false;
        }

        if (!int.TryParse(endpoint[(colon + 1)..], out port))
        {
            return false;
        }

        host = endpoint[..colon].Trim('[', ']');
        return !string.IsNullOrEmpty(host);
    }

    private static bool IsLoopbackHost(string host) =>
        host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
        (IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip));

    private CheckResult EvaluateIpConsistency(GuardianConfig config, NetworkSnapshot network)
    {
        if (config.IsCheckDisabled(GuardianCheckIds.IpConsistency))
        {
            return Skipped(GuardianCheckIds.IpConsistency, "出口 IP 稳定性");
        }

        var previousIp = !string.IsNullOrWhiteSpace(network.PreviousExitIp)
            ? network.PreviousExitIp
            : _lastExitIp;

        var status = CheckStatus.Ok;
        var detail = "首次记录出口 IP";
        if (!string.IsNullOrWhiteSpace(previousIp) && !string.IsNullOrWhiteSpace(network.ExitIp))
        {
            status = string.Equals(previousIp, network.ExitIp, StringComparison.OrdinalIgnoreCase)
                ? CheckStatus.Ok
                : CheckStatus.Warn;
            detail = $"{previousIp} → {network.ExitIp}";
        }

        if (network.IpDriftCount48h >= 3)
        {
            status = CheckStatus.Warn;
            detail += $"；48h 内出口 IP 出现 {network.IpDriftCount48h} 个不同地址，建议固定节点";
        }

        if (!string.IsNullOrWhiteSpace(network.ExitIp))
        {
            _lastExitIp = network.ExitIp;
        }

        return Result(GuardianCheckIds.IpConsistency, "出口 IP 稳定性", status, config.BlockOnWarning, detail);
    }

    private static CheckResult EvaluateTimezone(GuardianConfig config, NetworkSnapshot network)
    {
        if (config.IsCheckDisabled(GuardianCheckIds.Timezone))
        {
            return Skipped(GuardianCheckIds.Timezone, "时区一致性");
        }

        var status = CheckStatus.Warn;
        var detail = "无法根据当前出口解析时区";
        if (!string.IsNullOrWhiteSpace(network.ExitWindowsTimezone))
        {
            status = string.Equals(
                network.CurrentWindowsTimezone,
                network.ExitWindowsTimezone,
                StringComparison.OrdinalIgnoreCase)
                ? CheckStatus.Ok
                : CheckStatus.Warn;
            detail = status == CheckStatus.Ok
                ? $"系统时区 {network.CurrentWindowsTimezone}，出口时区 {network.ExitTimezone}"
                : $"系统时区 {network.CurrentWindowsTimezone}，出口时区 {network.ExitTimezone}，目标 {network.ExitWindowsTimezone}";
        }

        return Result(GuardianCheckIds.Timezone, "时区一致性", status, blocking: false, detail);
    }

    private static CheckResult EvaluateLocale(GuardianConfig config, NetworkSnapshot network)
    {
        if (config.IsCheckDisabled(GuardianCheckIds.Locale))
        {
            return Skipped(GuardianCheckIds.Locale, "系统地区 Locale");
        }

        if (string.IsNullOrWhiteSpace(network.CurrentLocale) || string.IsNullOrWhiteSpace(network.ExpectedLocale))
        {
            return Result(GuardianCheckIds.Locale, "系统地区 Locale", CheckStatus.Warn, blocking: false, "尚未读取到系统或目标地区格式");
        }

        var matched = string.Equals(network.CurrentLocale, network.ExpectedLocale, StringComparison.OrdinalIgnoreCase);
        return Result(
            GuardianCheckIds.Locale,
            "系统地区 Locale",
            matched ? CheckStatus.Ok : CheckStatus.Warn,
            blocking: false,
            matched
                ? $"系统地区格式 {network.CurrentLocale} 与出口目标一致"
                : $"系统地区 {network.CurrentLocale}（期望 {network.ExpectedLocale}，可在维护工具一键同步）");
    }

    private static CheckResult EvaluateDns(GuardianConfig config, NetworkSnapshot network)
    {
        if (config.IsCheckDisabled(GuardianCheckIds.Dns))
        {
            return Skipped(GuardianCheckIds.Dns, "DNS");
        }

        if (network.ProxyPathSkipped)
        {
            return OptionalResult(config, GuardianCheckIds.Dns, "DNS", CheckStatus.Fail, blockingWhenFail: true, "代理路径不可用，无法验证 DNS");
        }

        if (network.DnsServers.Count == 0)
        {
            return OptionalResult(config, GuardianCheckIds.Dns, "DNS", CheckStatus.Unknown, blockingWhenFail: true, "没有取得 VPN 网卡 DNS");
        }

        // If real DNS resolution was captured, validate Fake-IP tunnel on Fake-IP adapters
        if (Collected(network, GuardianCheckIds.Dns) && network.ResolvedClaudeIps is { Count: > 0 } &&
            network.ResolvedClaudeIps.All(ip => IPAddress.TryParse(ip, out _)))
        {
            var allFakeIp = network.ResolvedClaudeIps.All(ip => ip.StartsWith("198.18.", StringComparison.Ordinal));
            if (network.AdapterIsFakeIp && !allFakeIp)
            {
                return OptionalResult(
                    config,
                    GuardianCheckIds.Dns,
                    "DNS",
                    CheckStatus.Fail,
                    blockingWhenFail: true,
                    $"Fake-IP TUN 已在线，但 claude.ai 解析未走隧道（{string.Join(", ", network.ResolvedClaudeIps)}）");
            }

            return Result(
                GuardianCheckIds.Dns,
                "DNS",
                CheckStatus.Ok,
                blocking: true,
                $"DNS {string.Join(", ", network.DnsServers)}；{network.DnsProbeDetail}");
        }

        if (!string.IsNullOrWhiteSpace(network.DnsProbeDetail) &&
            (network.DnsProbeDetail.Contains("失败", StringComparison.OrdinalIgnoreCase) ||
             network.DnsProbeDetail.Contains("未解析", StringComparison.OrdinalIgnoreCase)))
        {
            return OptionalResult(
                config,
                GuardianCheckIds.Dns,
                "DNS",
                CheckStatus.Unknown,
                blockingWhenFail: true,
                $"DNS {string.Join(", ", network.DnsServers)}；{network.DnsProbeDetail}");
        }

        return OptionalResult(
            config,
            GuardianCheckIds.Dns,
            "DNS",
            CheckStatus.Unknown,
            blockingWhenFail: true,
            "未取得有效 DNS 解析结果；本项仅验证解析与 Fake-IP 特征，不证明完整 DNS 防泄漏");
    }

    private static CheckResult EvaluateIpv6(GuardianConfig config, NetworkSnapshot network)
    {
        var leakingNonTunAdapters = network.PublicIpv6Routes ?? Array.Empty<string>();
        if (leakingNonTunAdapters.Count > 0)
        {
            return Result(
                GuardianCheckIds.Ipv6,
                "IPv6 出口",
                CheckStatus.Fail,
                blocking: true,
                $"非 VPN 网卡存在公网/NAT64 IPv6 出站路由：{string.Join("、", leakingNonTunAdapters)}（存在双栈旁路泄漏风险）");
        }

        if (!Collected(network, GuardianCheckIds.Ipv6))
            return Result(GuardianCheckIds.Ipv6, "IPv6 出口", CheckStatus.Unknown, true,
                "IPv6 路由读取失败或尚未完成，无法排除旁路");

        var ipv6Status = CheckStatus.Ok;
        var ipv6Detail = "没有检测到在线公网 IPv6 地址或直连路由";
        if (network.HasIpv6 && string.IsNullOrWhiteSpace(network.ExitIpv6))
        {
            var hasNoPublicIpv6Egress = network.Ipv6ProbeDetail.Contains(
                "返回的地址不是 IPv6",
                StringComparison.OrdinalIgnoreCase);
            ipv6Status = hasNoPublicIpv6Egress ? CheckStatus.Ok : CheckStatus.Unknown;
            ipv6Detail = hasNoPublicIpv6Egress
                ? "VPN IPv6 路由已接管，但公网出口没有 IPv6 地址，未发现 IPv6 直连泄漏"
                : string.IsNullOrWhiteSpace(network.Ipv6ProbeDetail)
                    ? "检测到 VPN IPv6 路由，但没有取得公网 IPv6 出口"
                    : network.Ipv6ProbeDetail;
        }
        else if (network.HasIpv6 && !IsExpectedIpv6(network, config))
        {
            ipv6Status = CheckStatus.Fail;
            ipv6Detail = $"IPv6 出口 {network.ExitIpv6}，国家 {network.ExitIpv6Country}，与目标出口不一致";
        }
        else if (network.HasIpv6)
        {
            ipv6Detail = $"IPv6 出口 {network.ExitIpv6}，国家 {network.ExitIpv6Country}";
        }

        return Result(GuardianCheckIds.Ipv6, "IPv6 出口", ipv6Status, network.HasIpv6, ipv6Detail);
    }

    private static CheckResult EvaluateWebRtc(GuardianConfig config, NetworkSnapshot network)
    {
        if (config.IsCheckDisabled(GuardianCheckIds.WebRtc))
        {
            return Skipped(GuardianCheckIds.WebRtc, "WebRTC 泄露");
        }

        var stunAddresses = network.StunResults
            .Where(result => result.Status == "ok" && !string.IsNullOrWhiteSpace(result.Address))
            .Select(result => result.Address)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var nativeWebRtcStatus = stunAddresses.Length == 0
            ? CheckStatus.Unknown
            : !HasExpectedWebRtcAddress(network)
                ? CheckStatus.Unknown
                : stunAddresses.All(address =>
                    string.Equals(address, network.ExitIp, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(address, network.ExitIpv6, StringComparison.OrdinalIgnoreCase))
                    ? CheckStatus.Ok
                    : CheckStatus.Fail;
        var nativeWebRtcDetail = stunAddresses.Length == 0
            ? network.StunResults.Count == 0
                ? "没有可用的 STUN 探针"
                : BuildWebRtcUnknownDetail(network.StunResults)
            : !HasExpectedWebRtcAddress(network)
                ? $"STUN 地址 {string.Join(", ", stunAddresses)}，但当前 VPN 出口未知，无法确认是否泄露"
                : $"STUN 地址 {string.Join(", ", stunAddresses)}";
        var webrtcStatus = CombineWebRtcStatus(network, nativeWebRtcStatus);
        var detail = BuildWebRtcDetail(network, nativeWebRtcDetail);

        // Verified reject policy explains expected silence on native STUN when browser ICE reports no public leak.
        var verifiedRejectPolicy =
            string.Equals(WebRtcPolicies.Normalize(config.WebRtcPolicy), WebRtcPolicies.Reject, StringComparison.Ordinal) &&
            network.ClashRulesLoaded == true &&
            stunAddresses.Length == 0 &&
            nativeWebRtcStatus == CheckStatus.Unknown &&
            webrtcStatus == CheckStatus.Unknown &&
            (network.BrowserWebRtc is null ||
             (network.BrowserWebRtc.Supported &&
              network.BrowserWebRtc.Complete &&
              !network.BrowserWebRtc.Candidates.Any(c =>
                  c.Kind == "public" && (!HasExpectedWebRtcAddress(network) || !IsExpectedWebRtcAddress(c.Address, network)))));
        if (verifiedRejectPolicy)
        {
            return Result(
                GuardianCheckIds.WebRtc,
                "WebRTC 泄露",
                CheckStatus.Ok,
                blocking: true,
                $"STUN 端口已按 reject 策略验证拒绝（预期无响应）；{detail}");
        }

        // Confirmed WebRTC leak (Fail) MUST NEVER be downgraded by AllowOptionalFailures!
        if (webrtcStatus == CheckStatus.Fail)
        {
            return Result(GuardianCheckIds.WebRtc, "WebRTC 泄露", CheckStatus.Fail, blocking: true, detail);
        }

        if (webrtcStatus == CheckStatus.Warn)
        {
            return Result(
                GuardianCheckIds.WebRtc,
                "WebRTC 泄露",
                CheckStatus.Warn,
                blocking: false,
                $"原生 STUN 与浏览器公网候选均与出口一致，存在部分 ICE 解析告警；{detail}");
        }

        return OptionalResult(config, GuardianCheckIds.WebRtc, "WebRTC 泄露", webrtcStatus, blockingWhenFail: true, detail);
    }

    private static CheckResult EvaluateWfpPolicy(GuardianConfig config, NetworkSnapshot network)
    {
        var state = network.WfpPolicyState?.Trim().ToLowerInvariant() ?? "off";
        var detail = string.IsNullOrWhiteSpace(network.WfpPolicyDetail)
            ? $"WFP 状态：{state}"
            : network.WfpPolicyDetail;

        if (!config.WfpStrictEnabled)
        {
            var status = state switch
            {
                "active" => CheckStatus.Ok,
                "stale" => CheckStatus.Warn,
                _ => CheckStatus.Warn
            };
            return Result(GuardianCheckIds.WfpPolicy, "WFP 内核出站锁", status, blocking: false, detail);
        }

        return state == "active"
            ? Result(GuardianCheckIds.WfpPolicy, "WFP 内核出站锁", CheckStatus.Ok, blocking: true, detail)
            : Result(GuardianCheckIds.WfpPolicy, "WFP 内核出站锁", CheckStatus.Fail, blocking: true, detail);
    }

    private static CheckResult EvaluateClashRules(GuardianConfig config, NetworkSnapshot network)
    {
        if (config.IsCheckDisabled(GuardianCheckIds.ClashRules))
        {
            return Skipped(GuardianCheckIds.ClashRules, "Clash 置顶路由");
        }

        if (string.IsNullOrWhiteSpace(network.ClashRulesStatus))
        {
            return Result(GuardianCheckIds.ClashRules, "Clash 置顶路由", CheckStatus.Warn, blocking: false, "尚未获取 Clash 路由状态");
        }

        var status = network.ClashRulesStatus.ToLowerInvariant() switch
        {
            "ok" => CheckStatus.Ok,
            "fail" => CheckStatus.Fail,
            _ => CheckStatus.Warn
        };
        return OptionalResult(
            config,
            GuardianCheckIds.ClashRules,
            "Clash 置顶路由",
            status,
            blockingWhenFail: true,
            network.ClashRulesDetail);
    }

    private static CheckResult EvaluateClientLanguage(GuardianConfig config, NetworkSnapshot network)
    {
        if (config.IsCheckDisabled(GuardianCheckIds.ClientLanguage))
        {
            return Skipped(GuardianCheckIds.ClientLanguage, "Claude 客户端语言");
        }

        if (string.IsNullOrWhiteSpace(network.ClientLanguage))
        {
            return Result(
                GuardianCheckIds.ClientLanguage,
                "Claude 客户端语言",
                CheckStatus.Warn,
                blocking: false,
                "未能读取 Claude config.json 的 locale 设置（不代表 JS 运行态）");
        }

        var targetLocale = !string.IsNullOrWhiteSpace(network.ExpectedLocale)
            ? network.ExpectedLocale
            : CountryDefaults.GetExpectedLocale(config.ExpectedExitCountry ?? network.ExitCountry);
        var wantPrefix = targetLocale.Split('-')[0];
        var actualPrefix = network.ClientLanguage.Split('-')[0];
        var matched = string.Equals(actualPrefix, wantPrefix, StringComparison.OrdinalIgnoreCase);

        return Result(
            GuardianCheckIds.ClientLanguage,
            "Claude 客户端语言",
            matched ? CheckStatus.Ok : CheckStatus.Warn,
            blocking: false,
            matched
                ? $"Claude 配置语言={network.ClientLanguage}（匹配目标前缀 {wantPrefix}）"
                : $"Claude 配置语言={network.ClientLanguage}，期望 {wantPrefix} 前缀");
    }

    private static CheckResult EvaluateAsn(GuardianConfig config, NetworkSnapshot network)
    {
        if (config.IsCheckDisabled(GuardianCheckIds.Asn))
        {
            return Skipped(GuardianCheckIds.Asn, "ASN 网络类型");
        }

        if (string.IsNullOrWhiteSpace(network.AsnOrg))
        {
            return Result(
                GuardianCheckIds.Asn,
                "ASN 网络类型",
                CheckStatus.Warn,
                blocking: false,
                string.IsNullOrWhiteSpace(network.AsnDetail) ? "未获取到出口 ASN 信息" : network.AsnDetail);
        }

        var isIsp = string.Equals(network.AsnType, "Cable/DSL/ISP", StringComparison.OrdinalIgnoreCase);
        return Result(
            GuardianCheckIds.Asn,
            "ASN 网络类型",
            isIsp ? CheckStatus.Ok : CheckStatus.Warn,
            blocking: false,
            network.AsnDetail);
    }

    private static CheckResult EvaluateClaudeDomains(GuardianConfig config, NetworkSnapshot network)
    {
        if (config.IsCheckDisabled(GuardianCheckIds.ClaudeDomains))
        {
            return Skipped(GuardianCheckIds.ClaudeDomains, "Claude HTTPS");
        }

        if (network.ProxyPathSkipped)
        {
            return OptionalResult(config, GuardianCheckIds.ClaudeDomains, "Claude HTTPS", CheckStatus.Fail, blockingWhenFail: true, "代理路径失效，已跳过探测");
        }

        var valid = Collected(network, GuardianCheckIds.ClaudeDomains) && config.EffectiveClaudeDomains.All(domain =>
            network.ClaudeHttps.ContainsKey(domain)) && network.ClaudeHttps.Values.All(value =>
                int.TryParse(value, out var status) && status is >= 100 and <= 599);
        var accessWarning = valid && network.ClaudeHttps.Any(pair =>
            int.Parse(pair.Value) is < 200 or >= 400 &&
            !(pair.Key.Equals("api.anthropic.com", StringComparison.OrdinalIgnoreCase) && pair.Value == "401"));
        return OptionalResult(
            config,
            GuardianCheckIds.ClaudeDomains,
            "Claude HTTPS",
            !valid ? CheckStatus.Unknown : accessWarning ? CheckStatus.Warn : CheckStatus.Ok,
            blockingWhenFail: true,
            valid
                ? string.Join("，", network.ClaudeHttps.Select(pair => $"{pair.Key}={pair.Value}")) +
                  (accessWarning ? "；已收到响应，但存在访问/服务限制" : "；传输可达（API 401 表示需要认证）") + "；账号登录与发消息未测试"
                : "Claude 域名 HTTPS 未取得完整有效状态码；账号与消息能力未验证");
    }

    private static IReadOnlyList<CheckResult> EvaluateIpReputation(GuardianConfig config, NetworkSnapshot network)
    {
        var results = new List<CheckResult>(4);
        var rep = network.IpReputation;
        var unavailable = config.IpReputation is null || string.IsNullOrWhiteSpace(config.IpReputation.Url)
            ? "未配置信誉数据源（可在「检查与防护设置」中配置 HTTPS 接口）"
            : !string.IsNullOrWhiteSpace(network.IpReputationError)
                ? network.IpReputationError
                : rep is null
                    ? "信誉数据源探测失败或未返回可用数据"
                    : string.Empty;

        // 1. Score
        if (config.IsCheckDisabled(GuardianCheckIds.IpRepScore))
        {
            results.Add(Skipped(GuardianCheckIds.IpRepScore, "IP 纯净度"));
        }
        else if (!string.IsNullOrEmpty(unavailable))
        {
            results.Add(Result(GuardianCheckIds.IpRepScore, "IP 纯净度", CheckStatus.Warn, false, unavailable));
        }
        else if (rep!.Score.HasValue)
        {
            var threshold = config.IpReputation!.Threshold;
            var levelSuffix = string.IsNullOrWhiteSpace(rep.Level) ? string.Empty : $" · {rep.Level}";
            var dirty = threshold > 0 && rep.Score.Value >= threshold;
            results.Add(OptionalResult(
                config,
                GuardianCheckIds.IpRepScore,
                "IP 纯净度",
                dirty ? CheckStatus.Fail : CheckStatus.Ok,
                blockingWhenFail: true,
                $"风险分 {rep.Score.Value:0.#}{levelSuffix}" + (threshold > 0 ? $"（阈值 {threshold:0.#}）" : string.Empty)));
        }
        else
        {
            results.Add(Result(GuardianCheckIds.IpRepScore, "IP 纯净度", CheckStatus.Warn, false, "数据源未提供风险分（缺字段不视为无风险）"));
        }

        // 2. Proxy / VPN / Tor flags
        if (config.IsCheckDisabled(GuardianCheckIds.IpRepProxy))
        {
            results.Add(Skipped(GuardianCheckIds.IpRepProxy, "IP 代理标记"));
        }
        else if (!string.IsNullOrEmpty(unavailable))
        {
            results.Add(Result(GuardianCheckIds.IpRepProxy, "IP 代理标记", CheckStatus.Warn, false, unavailable));
        }
        else
        {
            var flags = new List<string>();
            var hit = false;
            var hasUnknown = false;
            void InspectFlag(bool? value, string label)
            {
                if (!value.HasValue)
                {
                    flags.Add($"{label} 未知");
                    hasUnknown = true;
                }
                else if (value.Value)
                {
                    flags.Add($"{label} 命中");
                    hit = true;
                }
                else
                {
                    flags.Add($"{label} 否");
                }
            }

            InspectFlag(rep!.IsProxy, "公开代理");
            InspectFlag(rep.IsVpn, "VPN");
            InspectFlag(rep.IsTor, "Tor");
            var status = hit ? CheckStatus.Fail : hasUnknown ? CheckStatus.Warn : CheckStatus.Ok;
            results.Add(OptionalResult(config, GuardianCheckIds.IpRepProxy, "IP 代理标记", status, blockingWhenFail: true, string.Join(" · ", flags)));
        }

        // 3. Hosting / Datacenter
        if (config.IsCheckDisabled(GuardianCheckIds.IpRepHosting))
        {
            results.Add(Skipped(GuardianCheckIds.IpRepHosting, "IP 机房属性"));
        }
        else if (!string.IsNullOrEmpty(unavailable))
        {
            results.Add(Result(GuardianCheckIds.IpRepHosting, "IP 机房属性", CheckStatus.Warn, false, unavailable));
        }
        else if (rep!.IsHosting.HasValue)
        {
            results.Add(Result(
                GuardianCheckIds.IpRepHosting,
                "IP 机房属性",
                rep.IsHosting.Value ? CheckStatus.Warn : CheckStatus.Ok,
                blocking: false,
                rep.IsHosting.Value ? "机房/数据中心地址" : "非机房地址"));
        }
        else
        {
            results.Add(Result(GuardianCheckIds.IpRepHosting, "IP 机房属性", CheckStatus.Warn, false, "数据源未提供机房属性"));
        }

        // 4. Blacklist
        if (config.IsCheckDisabled(GuardianCheckIds.IpRepBlacklist))
        {
            results.Add(Skipped(GuardianCheckIds.IpRepBlacklist, "IP 黑名单"));
        }
        else if (!string.IsNullOrEmpty(unavailable))
        {
            results.Add(Result(GuardianCheckIds.IpRepBlacklist, "IP 黑名单", CheckStatus.Warn, false, unavailable));
        }
        else if (rep!.BlacklistCount.HasValue)
        {
            var dirty = rep.BlacklistCount.Value >= 1;
            results.Add(OptionalResult(
                config,
                GuardianCheckIds.IpRepBlacklist,
                "IP 黑名单",
                dirty ? CheckStatus.Fail : CheckStatus.Ok,
                blockingWhenFail: true,
                dirty ? $"黑名单/滥用命中 {rep.BlacklistCount.Value:0.#} 项" : $"未命中（{rep.BlacklistCount.Value:0.#}）"));
        }
        else
        {
            results.Add(Result(GuardianCheckIds.IpRepBlacklist, "IP 黑名单", CheckStatus.Warn, false, "数据源未提供黑名单信息"));
        }

        return results;
    }

    private static CheckResult OptionalResult(
        GuardianConfig config,
        string id,
        string title,
        CheckStatus status,
        bool blockingWhenFail,
        string detail)
    {
        if (config.IsCheckDisabled(id))
        {
            return Skipped(id, title);
        }

        if (config.AllowOptionalFailures && (status == CheckStatus.Fail || status == CheckStatus.Unknown))
        {
            return Result(id, title, CheckStatus.Warn, blocking: false, $"非关键失败已降级（{detail}）");
        }

        var blocking = status == CheckStatus.Warn ? config.BlockOnWarning : blockingWhenFail;
        return Result(id, title, status, blocking, detail);
    }

    private static CheckResult Skipped(string id, string title) =>
        Result(id, title, CheckStatus.Skip, blocking: false, "用户已禁用（跳过不代表通过）");

    private static CheckStatus CombineWebRtcStatus(
        NetworkSnapshot network,
        CheckStatus nativeStatus)
    {
        if (network.BrowserWebRtc is null)
        {
            return nativeStatus;
        }

        var browser = network.BrowserWebRtc;
        if (nativeStatus == CheckStatus.Fail)
        {
            return CheckStatus.Fail;
        }

        var publicCandidates = browser.Candidates
            .Where(candidate => candidate.Kind == "public")
            .ToArray();
        if (publicCandidates.Length > 0 && !HasExpectedWebRtcAddress(network))
        {
            return CheckStatus.Unknown;
        }

        if (publicCandidates.Any(candidate => !IsExpectedWebRtcAddress(candidate.Address, network)))
        {
            return CheckStatus.Fail;
        }

        if (!browser.Supported ||
            !browser.Complete ||
            !string.Equals(browser.Status, "complete", StringComparison.OrdinalIgnoreCase))
        {
            return CheckStatus.Unknown;
        }

        if (browser.Errors is { Count: > 0 })
        {
            var verifiedLookupWarnings = nativeStatus == CheckStatus.Ok &&
                publicCandidates.Length > 0 &&
                network.StunResults.All(result =>
                    result.Status == "ok" && !string.IsNullOrWhiteSpace(result.Address)) &&
                browser.Errors.All(error =>
                    error.Code == 701 &&
                    error.Text.Contains("STUN host lookup received error", StringComparison.OrdinalIgnoreCase) &&
                    network.StunResults.Any(result => string.Equals(
                        error.Url,
                        $"stun:{result.Server}:{result.Port}",
                        StringComparison.OrdinalIgnoreCase)));
            return verifiedLookupWarnings ? CheckStatus.Warn : CheckStatus.Unknown;
        }

        if (nativeStatus != CheckStatus.Ok)
        {
            return nativeStatus;
        }

        return CheckStatus.Ok;
    }

    private static bool IsExpectedWebRtcAddress(string address, NetworkSnapshot network) =>
        string.Equals(address, network.ExitIp, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(address, network.ExitIpv6, StringComparison.OrdinalIgnoreCase);

    private static bool HasExpectedWebRtcAddress(NetworkSnapshot network) =>
        !string.IsNullOrWhiteSpace(network.ExitIp) ||
        !string.IsNullOrWhiteSpace(network.ExitIpv6);

    private static string BuildWebRtcUnknownDetail(IReadOnlyList<StunResult> results)
    {
        var details = string.Join(
            "；",
            results.Select(result => $"{result.Server}:{result.Port} {result.Status} {result.Detail}"));
        var allUnavailable = results.Count > 0 &&
                             results.All(result =>
                                 result.Status == "unknown" &&
                                 (result.Detail.Contains("STUN 超时", StringComparison.OrdinalIgnoreCase) ||
                                  result.Detail.Contains("未取得 IPv6 地址", StringComparison.OrdinalIgnoreCase)));
        return allUnavailable
            ? $"所有 STUN 请求均超时，当前无法证明 WebRTC 没有泄漏。通常表示 VPN/节点未接管 UDP，或 STUN 端口被阻断；{details}"
            : details;
    }

    private static string BuildWebRtcDetail(NetworkSnapshot network, string nativeDetail)
    {
        if (network.BrowserWebRtc is null)
        {
            return nativeDetail;
        }

        var browser = network.BrowserWebRtc;
        var candidates = browser.Candidates.Count == 0
            ? "浏览器没有返回可展示的候选地址"
            : string.Join(
                "；",
                browser.Candidates.Select(candidate => $"{candidate.Address}（{candidate.Kind}/{candidate.AddressFamily}）"));
        var errors = browser.Errors is { Count: > 0 }
            ? string.Join(
                "；",
                browser.Errors.Select(error => $"ICE 错误 {error.Url} code={error.Code} {error.Text}".Trim()))
            : "浏览器没有报告 ICE 错误";
        var browserDetail = $"浏览器 ICE {browser.Status}：{browser.Detail}；候选 {candidates}；{errors}";
        return $"{browserDetail}；原生 STUN {nativeDetail}";
    }

    private static bool IsExpectedExit(NetworkSnapshot network, GuardianConfig config)
    {
        if (string.Equals(network.ExitCountry, "CN", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(config.ExpectedExitCountry, "CN", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(config.ExpectedExitIp) &&
            !string.Equals(config.ExpectedExitIp, network.ExitIp, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return string.IsNullOrWhiteSpace(config.ExpectedExitCountry) ||
               string.Equals(config.ExpectedExitCountry, network.ExitCountry, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsExpectedIpv6(NetworkSnapshot network, GuardianConfig config)
    {
        if (!string.IsNullOrWhiteSpace(config.ExpectedExitCountry) &&
            !string.Equals(config.ExpectedExitCountry, network.ExitIpv6Country, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return string.IsNullOrWhiteSpace(network.ExitCountry) ||
               string.IsNullOrWhiteSpace(network.ExitIpv6Country) ||
               string.Equals(network.ExitCountry, network.ExitIpv6Country, StringComparison.OrdinalIgnoreCase);
    }

    private static List<CheckResult> AttachEvidence(
        List<CheckResult> checks,
        GuardianConfig config,
        NetworkSnapshot network,
        IReadOnlyList<ProcessInfo> processes)
    {
        var enriched = new List<CheckResult>(checks.Count);
        foreach (var check in checks)
        {
            var ev = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (check.Status == CheckStatus.Skip)
            {
                ev["skipped"] = "true";
            }
            else
            {
                switch (check.Id)
                {
                    case GuardianCheckIds.ClaudeProcess:
                        ev["count"] = processes.Count.ToString();
                        ev["pids"] = string.Join(",", processes.Select(p => p.ProcessId));
                        break;
                    case GuardianCheckIds.ProxyClient:
                        ev["mode"] = ProxyClientModes.Normalize(config.ProxyClientMode);
                        ev["client"] = network.ProxyClientName;
                        ev["alive"] = network.ProxyClientAlive ? "true" : "false";
                        break;
                    case GuardianCheckIds.VpnAdapter:
                        ev["adapter"] = network.AdapterName;
                        ev["fake_ip"] = network.AdapterIsFakeIp ? "true" : "false";
                        ev["guid"] = network.AdapterGuid;
                        break;
                    case GuardianCheckIds.DefaultRoute:
                        ev["gateway"] = network.Gateway;
                        ev["has_default_route"] = network.AdapterHasDefaultRoute ? "true" : "false";
                        ev["best_routes"] = string.Join(";", (network.DestinationRoutes ?? Array.Empty<DestinationRoute>())
                            .Select(route => $"{route.Destination}:if={route.InterfaceIndex},tun={route.ExpectedInterfaceIndex},ok={route.Succeeded}"));
                        break;
                    case GuardianCheckIds.EgressIp:
                        ev["ip"] = network.ExitIp;
                        ev["country"] = network.ExitCountry;
                        ev["source"] = network.ExitIpSource;
                        ev["system_proxy"] = network.SystemProxyConfigured ? "true" : "false";
                        if (network.SystemProxyConfigured)
                        {
                            ev["system_proxy_uri"] = network.SystemProxyUri;
                            ev["tun_ip"] = network.TunDirectExitIp;
                            ev["tun_country"] = network.TunDirectExitCountry;
                        }
                        break;
                    case GuardianCheckIds.IpConsistency:
                        ev["previous_ip"] = network.PreviousExitIp;
                        ev["drift_48h"] = network.IpDriftCount48h.ToString();
                        break;
                    case GuardianCheckIds.Timezone:
                        ev["exit_iana"] = network.ExitTimezone;
                        ev["exit_win"] = network.ExitWindowsTimezone;
                        ev["current_win"] = network.CurrentWindowsTimezone;
                        break;
                    case GuardianCheckIds.Locale:
                        ev["current"] = network.CurrentLocale;
                        ev["expected"] = network.ExpectedLocale;
                        break;
                    case GuardianCheckIds.Dns:
                        ev["servers"] = string.Join(",", network.DnsServers);
                        ev["claude_ips"] = string.Join(",", network.ResolvedClaudeIps ?? Array.Empty<string>());
                        ev["fake_ip"] = network.AdapterIsFakeIp ? "true" : "false";
                        break;
                    case GuardianCheckIds.Ipv6:
                        ev["has_ipv6"] = network.HasIpv6 ? "true" : "false";
                        ev["exit_ipv6"] = network.ExitIpv6;
                        ev["exit_ipv6_country"] = network.ExitIpv6Country;
                        ev["non_vpn_routes"] = string.Join(",", network.PublicIpv6Routes ?? Array.Empty<string>());
                        break;
                    case GuardianCheckIds.WebRtc:
                        ev["policy"] = WebRtcPolicies.Normalize(config.WebRtcPolicy);
                        ev["stun_ok"] = network.StunResults.Count(r => r.Status == "ok").ToString();
                        ev["browser_status"] = network.BrowserWebRtc?.Status ?? "none";
                        ev["public_candidates"] = string.Join(
                            ",",
                            network.BrowserWebRtc?.Candidates.Where(c => c.Kind == "public").Select(c => c.Address)
                            ?? Array.Empty<string>());
                        break;
                    case GuardianCheckIds.ActiveConnections:
                        ev["total"] = network.ActiveConnections.Count.ToString();
                        ev["udp_bound_endpoints"] = (network.UdpEndpoints?.Count ?? 0).ToString();
                        ev["udp_semantics"] = "bound endpoints; not observed sends";
                        ev["unexpected"] = check.Status == CheckStatus.Ok ? "0" : "nonzero";
                        break;
                    case GuardianCheckIds.HelperService:
                        ev["alive"] = network.HelperAlive ? "true" : "false";
                        break;
                    case GuardianCheckIds.WfpPolicy:
                        ev["state"] = network.WfpPolicyState;
                        ev["strict"] = config.WfpStrictEnabled ? "true" : "false";
                        ev["allow_loopback"] = config.WfpAllowLoopback ? "true" : "false";
                        break;
                    case GuardianCheckIds.FirewallReadiness:
                        ev["api_ok"] = network.FirewallApiOk ? "true" : "false";
                        ev["active_rules"] = network.FirewallActiveRuleCount.ToString();
                        ev["policy_effective"] = network.FirewallPolicyEffective?.ToString() ?? "unknown";
                        break;
                    case GuardianCheckIds.TcpOnlyPolicy:
                        ev["enabled"] = config.TcpOnlyEnabled.ToString();
                        ev["state"] = network.TcpOnlyState ?? "unknown";
                        ev["verification"] = "effective rule readback; packet capture not performed";
                        break;
                    case GuardianCheckIds.ClashRules:
                        ev["mode"] = network.ClashMode;
                        ev["loaded"] = network.ClashRulesLoaded?.ToString().ToLowerInvariant() ?? "unknown";
                        ev["policy"] = WebRtcPolicies.Normalize(config.WebRtcPolicy);
                        break;
                    case GuardianCheckIds.ClientLanguage:
                        ev["language"] = network.ClientLanguage;
                        ev["expected"] = network.ExpectedLocale;
                        break;
                    case GuardianCheckIds.Asn:
                        ev["org"] = network.AsnOrg;
                        ev["type"] = network.AsnType;
                        break;
                    case GuardianCheckIds.ClaudeDomains:
                        ev["domains"] = string.Join(",", network.ClaudeHttps.Keys);
                        ev["statuses"] = string.Join(",", network.ClaudeHttps.Select(kv => $"{kv.Key}={kv.Value}"));
                        break;
                    case GuardianCheckIds.IpRepScore:
                        ev["configured"] = config.IpReputation is not null && !string.IsNullOrWhiteSpace(config.IpReputation.Url) ? "true" : "false";
                        ev["score"] = network.IpReputation?.Score?.ToString("0.#") ?? "";
                        ev["threshold"] = config.IpReputation?.Threshold.ToString("0.#") ?? "";
                        break;
                    case GuardianCheckIds.IpRepProxy:
                        ev["proxy"] = network.IpReputation?.IsProxy?.ToString().ToLowerInvariant() ?? "unknown";
                        ev["vpn"] = network.IpReputation?.IsVpn?.ToString().ToLowerInvariant() ?? "unknown";
                        ev["tor"] = network.IpReputation?.IsTor?.ToString().ToLowerInvariant() ?? "unknown";
                        break;
                    case GuardianCheckIds.IpRepHosting:
                        ev["hosting"] = network.IpReputation?.IsHosting?.ToString().ToLowerInvariant() ?? "unknown";
                        break;
                    case GuardianCheckIds.IpRepBlacklist:
                        ev["blacklist_count"] = network.IpReputation?.BlacklistCount?.ToString("0.#") ?? "unknown";
                        break;
                }
            }

            var observation = network.Observations?.GetValueOrDefault(check.Id);
            var observedAt = check.Status == CheckStatus.Skip ? null : observation?.ObservedAt;
            ev["collection_state"] = check.Status == CheckStatus.Skip ? "disabled" : observation is null ? "not-collected"
                : observation.Succeeded ? "collected" : "failed";
            ev["observed_at"] = observedAt?.ToString("O") ?? "";
            ev["cached"] = observation?.IsCached == true ? "true" : "false";
            if (!string.IsNullOrWhiteSpace(observation?.Error)) ev["collection_error"] = observation.Error;
            enriched.Add(check with { Evidence = ev, ObservedAt = observedAt, IsCached = observation?.IsCached == true });
        }

        return enriched;
    }

    private static CheckResult Result(
        string id,
        string title,
        CheckStatus status,
        bool blocking,
        string detail)
    {
        return new CheckResult(
            id,
            title,
            status,
            blocking,
            detail,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));
    }
}
