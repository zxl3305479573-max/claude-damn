namespace ClaudeDesktopGuardian.Core;

public sealed class GuardianCheckEngine
{
    private readonly IEnvironmentProbe _probe;
    private readonly IProcessInspector _processInspector;
    private readonly IWebRtcBrowserProbe? _browserProbe;
    private readonly IGuardianClock _clock;
    private string _lastExitIp = string.Empty;
    private WebRtcBrowserResult? _lastBrowserWebRtc;

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
        var processes = _processInspector.FindClaudeProcessTree();
        var network = await _probe.CaptureNetworkAsync(config, processes, full, cancellationToken);
        if (full && _browserProbe is not null)
        {
            var browserWebRtc = await _browserProbe.ProbeAsync(
                config.EffectiveStunUrls,
                cancellationToken);
            _lastBrowserWebRtc = browserWebRtc;
            network = network with { BrowserWebRtc = browserWebRtc };
        }
        else if (!full && _lastBrowserWebRtc is not null)
        {
            network = network with { BrowserWebRtc = _lastBrowserWebRtc };
        }

        var checks = new List<CheckResult>();

        checks.Add(Result(
            "claude-process",
            "Claude 进程树",
            processes.Count > 0 ? CheckStatus.Ok : CheckStatus.Warn,
            false,
            processes.Count > 0 ? $"已识别 {processes.Count} 个进程" : "当前没有识别到 Claude Desktop 进程"));

        checks.Add(Result(
            "vpn-adapter",
            "VPN/TUN 网卡",
            string.IsNullOrWhiteSpace(network.AdapterName) ? CheckStatus.Fail : CheckStatus.Ok,
            true,
            string.IsNullOrWhiteSpace(network.AdapterName)
                ? "没有识别到在线 VPN/TUN 网卡"
                : $"{network.AdapterName} / {network.AdapterDescription}"));

        checks.Add(Result(
            "default-route",
            "默认路由",
            string.IsNullOrWhiteSpace(network.Gateway) ? CheckStatus.Unknown : CheckStatus.Ok,
            true,
            string.IsNullOrWhiteSpace(network.Gateway)
                ? "VPN 网卡没有可用 IPv4 网关"
                : $"网关 {network.Gateway}"));

        var exitStatus = string.IsNullOrWhiteSpace(network.ExitIp)
            ? CheckStatus.Unknown
            : IsExpectedExit(network, config) ? CheckStatus.Ok : CheckStatus.Fail;
        checks.Add(Result(
            "egress-ip",
            "出口 IP",
            exitStatus,
            true,
            string.IsNullOrWhiteSpace(network.ExitIp)
                ? "无法取得当前出口 IP"
                : $"当前出口 {network.ExitIp}，国家 {network.ExitCountry}"));

        var timezoneStatus = CheckStatus.Warn;
        var timezoneDetail = "无法根据当前出口解析时区";
        if (!string.IsNullOrWhiteSpace(network.ExitWindowsTimezone))
        {
            timezoneStatus = string.Equals(
                network.CurrentWindowsTimezone,
                network.ExitWindowsTimezone,
                StringComparison.OrdinalIgnoreCase)
                ? CheckStatus.Ok
                : CheckStatus.Warn;
            timezoneDetail = timezoneStatus == CheckStatus.Ok
                ? $"系统时区 {network.CurrentWindowsTimezone}，出口时区 {network.ExitTimezone}"
                : $"系统时区 {network.CurrentWindowsTimezone}，出口时区 {network.ExitTimezone}，目标 {network.ExitWindowsTimezone}";
        }
        checks.Add(Result(
            "timezone",
            "时区一致性",
            timezoneStatus,
            false,
            timezoneDetail));

        var ipStatus = CheckStatus.Ok;
        var ipDetail = "首次记录出口 IP";
        if (!string.IsNullOrWhiteSpace(_lastExitIp) && !string.IsNullOrWhiteSpace(network.ExitIp))
        {
            ipStatus = string.Equals(_lastExitIp, network.ExitIp, StringComparison.OrdinalIgnoreCase)
                ? CheckStatus.Ok
                : CheckStatus.Warn;
            ipDetail = $"{_lastExitIp} → {network.ExitIp}";
        }
        if (!string.IsNullOrWhiteSpace(network.ExitIp))
        {
            _lastExitIp = network.ExitIp;
        }
        checks.Add(Result("ip-consistency", "出口 IP 稳定性", ipStatus, config.BlockOnWarning, ipDetail));

        var dnsStatus = network.DnsServers.Count > 0 ? CheckStatus.Ok : CheckStatus.Unknown;
        checks.Add(Result(
            "dns",
            "DNS",
            dnsStatus,
            true,
            dnsStatus == CheckStatus.Ok
                ? $"DNS {string.Join(", ", network.DnsServers)}"
                : "没有取得 VPN 网卡 DNS"));

        var ipv6Status = CheckStatus.Ok;
        var ipv6Detail = "没有检测到在线公网 IPv6 地址";
        if (network.HasIpv6 && string.IsNullOrWhiteSpace(network.ExitIpv6))
        {
            var hasNoPublicIpv6Egress = network.Ipv6ProbeDetail.Contains(
                "返回的地址不是 IPv6",
                StringComparison.OrdinalIgnoreCase);
            ipv6Status = hasNoPublicIpv6Egress
                ? CheckStatus.Ok
                : CheckStatus.Unknown;
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

        checks.Add(Result("ipv6", "IPv6 出口", ipv6Status, network.HasIpv6, ipv6Detail));

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
        var webrtcDetail = nativeWebRtcDetail;
        checks.Add(Result(
            "webrtc",
            "WebRTC 泄露",
            webrtcStatus,
            true,
            BuildWebRtcDetail(network, webrtcDetail)));

        checks.Add(Result(
            "firewall-readiness",
            "防火墙保护",
            CheckStatus.Ok,
            false,
            "由管理员助手在阻断动作中确认规则状态"));

        if (full)
        {
            var httpsOk = network.ClaudeHttps.Count > 0 &&
                          network.ClaudeHttps.Values.All(value =>
                              value != "timeout" && value != "HttpRequestException");
            checks.Add(Result(
                "claude-domains",
                "Claude HTTPS",
                httpsOk ? CheckStatus.Ok : CheckStatus.Unknown,
                true,
                httpsOk
                    ? string.Join("，", network.ClaudeHttps.Select(pair => $"{pair.Key}={pair.Value}"))
                    : "Claude 域名 HTTPS 探测没有取得有效结果"));
        }

        return new GuardianReport(_clock.UtcNow, checks, network, processes);
    }

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
        if (publicCandidates.Length > 0 &&
            !HasExpectedWebRtcAddress(network))
        {
            return CheckStatus.Unknown;
        }

        if (publicCandidates.Any(candidate =>
                !IsExpectedWebRtcAddress(candidate.Address, network)))
        {
            return CheckStatus.Fail;
        }

        if (browser.Errors is { Count: > 0 })
        {
            return CheckStatus.Unknown;
        }

        if (!browser.Supported ||
            !browser.Complete ||
            !string.Equals(browser.Status, "complete", StringComparison.OrdinalIgnoreCase))
        {
            return CheckStatus.Unknown;
        }

        if (nativeStatus != CheckStatus.Ok)
        {
            return nativeStatus;
        }

        return CheckStatus.Ok;
    }

    private static bool IsExpectedWebRtcAddress(
        string address,
        NetworkSnapshot network)
    {
        return string.Equals(address, network.ExitIp, StringComparison.OrdinalIgnoreCase) ||
               string.Equals(address, network.ExitIpv6, StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasExpectedWebRtcAddress(NetworkSnapshot network)
    {
        return !string.IsNullOrWhiteSpace(network.ExitIp) ||
               !string.IsNullOrWhiteSpace(network.ExitIpv6);
    }

    private static string BuildWebRtcUnknownDetail(IReadOnlyList<StunResult> results)
    {
        var details = string.Join(
            "；",
            results.Select(result =>
                $"{result.Server}:{result.Port} {result.Status} {result.Detail}"));
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
                browser.Candidates.Select(candidate =>
                    $"{candidate.Address}（{candidate.Kind}/{candidate.AddressFamily}）"));
        var errors = browser.Errors is { Count: > 0 }
            ? string.Join(
                "；",
                browser.Errors.Select(error =>
                    $"ICE 错误 {error.Url} code={error.Code} {error.Text}".Trim()))
            : "浏览器没有报告 ICE 错误";
        var browserDetail =
            $"浏览器 ICE {browser.Status}：{browser.Detail}；候选 {candidates}；{errors}";
        return $"{browserDetail}；原生 STUN {nativeDetail}";
    }

    private static bool IsExpectedExit(NetworkSnapshot network, GuardianConfig config)
    {
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

