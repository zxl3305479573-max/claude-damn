using System.Text.Json.Serialization;

namespace ClaudeDesktopGuardian.Core;

public enum CheckStatus
{
    Ok,
    Warn,
    Fail,
    Unknown,
    Skip
}

public static class ProxyClientModes
{
    public const string Auto = "auto";
    public const string ClashVerge = "clash-verge";
    public const string FlClash = "flclash";
    public const string SingBox = "sing-box";
    public const string ClashX = "clashx";
    public const string Surge = "surge";
    public const string WireGuard = "wireguard";
    public const string Other = "other";

    public static readonly IReadOnlyList<string> All = new[]
    {
        Auto,
        ClashVerge,
        FlClash,
        SingBox,
        ClashX,
        Surge,
        WireGuard,
        Other
    };

    public static bool IsValid(string? mode) =>
        !string.IsNullOrWhiteSpace(mode) &&
        All.Any(item => string.Equals(item, mode.Trim(), StringComparison.OrdinalIgnoreCase));

    public static string Normalize(string? mode) =>
        All.FirstOrDefault(item => string.Equals(item, mode?.Trim(), StringComparison.OrdinalIgnoreCase))
        ?? Auto;

    public static string DisplayName(string? mode) => Normalize(mode) switch
    {
        ClashVerge => "Clash Verge",
        FlClash => "FlClash",
        SingBox => "sing-box",
        ClashX => "ClashX",
        Surge => "Surge",
        WireGuard => "WireGuard",
        Other => "其他 TUN 客户端",
        _ => "自动识别 (auto)"
    };
}

public static class WebRtcPolicies
{
    public const string Proxy = "proxy";
    public const string Reject = "reject";

    public static bool IsValid(string? policy) =>
        string.Equals(policy?.Trim(), Proxy, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(policy?.Trim(), Reject, StringComparison.OrdinalIgnoreCase);

    public static string Normalize(string? policy) =>
        string.Equals(policy?.Trim(), Reject, StringComparison.OrdinalIgnoreCase) ? Reject : Proxy;

    public static string DisplayName(string? policy) => Normalize(policy) switch
    {
        Reject => "拒绝 STUN UDP (reject)",
        _ => "代理转发 STUN UDP (proxy)"
    };
}

public static class GuardianCheckIds
{
    public const string ClaudeProcess = "claude-process";
    public const string ProxyClient = "proxy-client";
    public const string VpnAdapter = "vpn-adapter";
    public const string DefaultRoute = "default-route";
    public const string EgressIp = "egress-ip";
    public const string IpConsistency = "ip-consistency";
    public const string Timezone = "timezone";
    public const string Locale = "locale";
    public const string Dns = "dns";
    public const string Ipv6 = "ipv6";
    public const string WebRtc = "webrtc";
    public const string ActiveConnections = "active-connections";
    public const string HelperService = "helper-service";
    public const string WfpPolicy = "wfp-policy";
    public const string FirewallReadiness = "firewall-readiness";
    public const string TcpOnlyPolicy = "tcp-only-policy";
    public const string ClashRules = "clash-rules";
    public const string ClientLanguage = "client-language";
    public const string Asn = "asn";
    public const string ClaudeDomains = "claude-domains";
    public const string IpRepScore = "ip-rep-score";
    public const string IpRepProxy = "ip-rep-proxy";
    public const string IpRepHosting = "ip-rep-hosting";
    public const string IpRepBlacklist = "ip-rep-blacklist";

    public static readonly IReadOnlyList<string> OptionalIds = new[]
    {
        IpConsistency,
        Timezone,
        Locale,
        Dns,
        WebRtc,
        ClashRules,
        ClientLanguage,
        Asn,
        ClaudeDomains,
        IpRepScore,
        IpRepProxy,
        IpRepHosting,
        IpRepBlacklist
    };

    public static readonly IReadOnlyList<string> IpReputationIds = new[]
    {
        IpRepScore,
        IpRepProxy,
        IpRepHosting,
        IpRepBlacklist
    };

    public static readonly IReadOnlyDictionary<string, string> OptionalTitles =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [IpConsistency] = "出口 IP 稳定性 / 48h 漂移",
            [Timezone] = "时区一致性",
            [Locale] = "系统地区 Locale",
            [Dns] = "DNS 隧道验证",
            [WebRtc] = "WebRTC 泄露（STUN + ICE）",
            [ClashRules] = "Clash 置顶路由",
            [ClientLanguage] = "Claude 客户端语言",
            [Asn] = "ASN 网络类型",
            [ClaudeDomains] = "Claude HTTPS 生态可达性",
            [IpRepScore] = "IP 纯净度（风险分）",
            [IpRepProxy] = "IP 代理标记",
            [IpRepHosting] = "IP 机房属性",
            [IpRepBlacklist] = "IP 黑名单"
        };

    public static bool IsOptional(string id) =>
        OptionalIds.Contains(id, StringComparer.OrdinalIgnoreCase);
}

public sealed record CheckResult(
    string Id,
    string Title,
    CheckStatus Status,
    bool Blocking,
    string Detail,
    IReadOnlyDictionary<string, string> Evidence,
    DateTimeOffset? ObservedAt = null,
    bool IsCached = false)
{
    public bool Passed =>
        Status == CheckStatus.Ok ||
        Status == CheckStatus.Skip ||
        (Status == CheckStatus.Warn && !Blocking);

    public string StatusSymbol => Status switch
    {
        CheckStatus.Ok => "✓",
        CheckStatus.Warn => "⚠",
        CheckStatus.Fail => "✕",
        CheckStatus.Skip => "⏭",
        _ => "?"
    };

    public string StatusLabel => Status switch
    {
        CheckStatus.Ok => "✓ 通过",
        CheckStatus.Warn => "⚠ 警告",
        CheckStatus.Fail => "✕ 失败",
        CheckStatus.Skip => "⏭ 已跳过",
        _ => "? 未验证"
    };
}

public sealed record ProcessInfo(
    int ProcessId,
    int ParentProcessId,
    string Name,
    string Path,
    string UserSid);

public sealed record StunResult(
    string Server,
    int Port,
    string Status,
    string Address,
    string Detail);

public sealed record WebRtcCandidate(
    string Address,
    string Kind,
    string AddressFamily);

public sealed record WebRtcIceError(
    string Url,
    int Code,
    string Text);

public sealed record WebRtcBrowserResult(
    bool Supported,
    string Status,
    bool Complete,
    IReadOnlyList<WebRtcCandidate> Candidates,
    string Detail,
    string Error = "",
    IReadOnlyList<WebRtcIceError>? Errors = null)
{
    public static WebRtcBrowserResult Unsupported(string detail) =>
        new(false, "unsupported", false, Array.Empty<WebRtcCandidate>(), detail);
}

public sealed record IpReputationConfig(
    string Url = "",
    string Key = "",
    double Threshold = 25,
    int CacheDays = 7)
{
    public const string DefaultFreeUrl = "https://api.ipquery.io/{ip}";

    public static IpReputationConfig CreateDefault() =>
        new(DefaultFreeUrl, string.Empty, 25, 7);
}

public sealed record IpReputationRecord(
    DateTimeOffset CheckedAt,
    double? Score = null,
    string? Level = null,
    bool? IsProxy = null,
    bool? IsVpn = null,
    bool? IsTor = null,
    bool? IsHosting = null,
    double? BlacklistCount = null);

public sealed record CollectionObservation(
    bool Succeeded,
    DateTimeOffset ObservedAt,
    string Error = "",
    bool IsCached = false);

public sealed record TransportEndpoint(int ProcessId, string Protocol, string LocalAddress, int LocalPort,
    string RemoteAddress = "", int RemotePort = 0);

public sealed record DestinationRoute(string Destination, int InterfaceIndex, int ExpectedInterfaceIndex,
    bool Succeeded, string Error = "")
{
    public bool Matches => Succeeded && InterfaceIndex > 0 && InterfaceIndex == ExpectedInterfaceIndex;
}

public sealed record NetworkSnapshot(
    string AdapterName,
    string AdapterDescription,
    string LocalAddress,
    string Gateway,
    string ExitIp,
    string ExitCountry,
    string ExitIpv6,
    string ExitIpv6Country,
    IReadOnlyList<string> DnsServers,
    IReadOnlyList<StunResult> StunResults,
    IReadOnlyList<string> ActiveConnections,
    bool HasIpv6,
    IReadOnlyDictionary<string, string> ClaudeHttps,
    string ExitTimezone = "",
    string ExitWindowsTimezone = "",
    string CurrentWindowsTimezone = "",
    string Ipv6ProbeDetail = "",
    string Ipv4ProbeDetail = "",
    WebRtcBrowserResult? BrowserWebRtc = null,
    string AdapterGuid = "",
    bool AdapterIsFakeIp = false,
    bool AdapterHasDefaultRoute = true,
    string AdapterDiagnostic = "",
    string ProxyClientName = "",
    bool ProxyClientAlive = true,
    string ProxyClientDetail = "",
    string ExitIpSource = "",
    bool ProxyPathSkipped = false,
    IReadOnlyList<string>? ResolvedClaudeIps = null,
    string DnsProbeDetail = "",
    IReadOnlyList<string>? PublicIpv6Routes = null,
    string CurrentLocale = "",
    string ExpectedLocale = "",
    string ClientLanguage = "",
    string ClientLanguageSource = "",
    string AsnOrg = "",
    string AsnType = "",
    string AsnDetail = "",
    string ClashMode = "",
    string ClashRulesStatus = "",
    string ClashRulesDetail = "",
    bool? ClashRulesLoaded = null,
    string WfpPolicyState = "off",
    string WfpPolicyDetail = "",
    IpReputationRecord? IpReputation = null,
    string IpReputationError = "",
    int IpDriftCount48h = 0,
    string PreviousExitIp = "",
    bool HelperAlive = true,
    string HelperDetail = "",
    bool FirewallApiOk = true,
    int FirewallActiveRuleCount = 0,
    string FirewallDetail = "",
    bool SystemProxyConfigured = false,
    string SystemProxyUri = "",
    string TunDirectExitIp = "",
    string TunDirectExitCountry = "",
    string TunDirectProbeDetail = "",
    long LastCycleDurationMs = 0,
    bool LastCycleTimedOut = false,
    IReadOnlyDictionary<string, CollectionObservation>? Observations = null,
    IReadOnlyList<TransportEndpoint>? UdpEndpoints = null,
    IReadOnlyList<DestinationRoute>? DestinationRoutes = null,
    string NetworkContext = "",
    DateTimeOffset? CapturedAt = null,
    bool ContextChanged = false,
    bool? FirewallPolicyEffective = null,
    string? TcpOnlyState = null,
    string TcpOnlyDetail = "");

public sealed record LaunchGateDecision(
    bool Allowed,
    string Reason,
    IReadOnlyList<CheckResult> BlockingFailures);

public sealed record HelperStatusSnapshot(
    bool HelperAlive,
    string HelperDetail,
    string? WfpState,
    string? WfpDetail,
    bool FirewallApiOk,
    int FirewallActiveRuleCount,
    string FirewallDetail,
    bool? FirewallPolicyEffective = null,
    string? TcpOnlyState = null,
    string TcpOnlyDetail = "");

public sealed record GuardianReport(
    DateTimeOffset ObservedAt,
    IReadOnlyList<CheckResult> Checks,
    NetworkSnapshot Network,
    IReadOnlyList<ProcessInfo> ProtectedProcesses)
{
    public bool HasConfirmedWebRtcLeak =>
        Checks.Any(check =>
            check.Id == GuardianCheckIds.WebRtc &&
            check.Status == CheckStatus.Fail);

    public bool CanRecover =>
        Checks.All(check =>
            check.Status == CheckStatus.Ok ||
            check.Status == CheckStatus.Skip ||
            (check.Status == CheckStatus.Warn && !check.Blocking));

    public IReadOnlyList<CheckResult> BlockingFailures =>
        Checks.Where(check =>
            check.Blocking &&
            check.Status != CheckStatus.Ok &&
            check.Status != CheckStatus.Skip).ToArray();

    public string TripReason =>
        string.Join("；", BlockingFailures.Select(check =>
            $"{check.Title}（{check.Status}）：{check.Detail}"));
}

public sealed record GuardianState(
    bool Blocked,
    string TripReason,
    DateTimeOffset? BlockedAt,
    DateTimeOffset? LastCheckedAt,
    bool TimezoneOverrideActive = false,
    string? OriginalWindowsTimezone = null,
    string? AppliedWindowsTimezone = null,
    DateTimeOffset? TimezoneOverrideAt = null,
    bool IgnoreWebRtc = false,
    bool CompactWindowEnabled = false);

public sealed record GuardianConfig(
    string? VpnAdapterPattern = null,
    string? ExpectedExitCountry = null,
    string? ExpectedExitIp = null,
    int LightIntervalSeconds = 5,
    int FullIntervalMinutes = 30,
    bool BlockOnWarning = false,
    IReadOnlyList<string>? ClaudeDomains = null,
    IReadOnlyList<(string Host, int Port)>? StunServers = null,
    string ProxyClientMode = ProxyClientModes.Auto,
    string? ExpectedLocale = null,
    string? FlClashController = null,
    string ClashProxyGroup = "GLOBAL",
    bool WfpStrictEnabled = false,
    bool WfpAllowLoopback = false,
    bool AllowOptionalFailures = false,
    bool LoggingEnabled = true,
    IReadOnlyList<string>? DisabledOptionalChecks = null,
    IpReputationConfig? IpReputation = null,
    string WebRtcPolicy = WebRtcPolicies.Proxy,
    bool TcpOnlyEnabled = false)
{
    [JsonIgnore]
    public IReadOnlyList<string> EffectiveClaudeDomains =>
        ClaudeDomains is { Count: > 0 }
            ? ClaudeDomains
            : new[]
            {
                "api.anthropic.com",
                "platform.claude.com",
                "claude.ai",
                "claude.com",
                "anthropic.com"
            };

    [JsonIgnore]
    public IReadOnlyList<(string Host, int Port)> EffectiveStunServers =>
        StunServers is { Count: > 0 }
            ? StunServers
            : new[]
            {
                ("stun.cloudflare.com", 3478),
                ("stun.l.google.com", 19302),
                ("stun.miwifi.com", 3478),
                ("stun.chat.bilibili.com", 3478)
            };

    [JsonIgnore]
    public IReadOnlyList<string> EffectiveStunUrls =>
        EffectiveStunServers
            .Select(server => $"stun:{server.Host}:{server.Port}")
            .ToArray();

    public bool IsCheckDisabled(string id) =>
        GuardianCheckIds.IsOptional(id) &&
        DisabledOptionalChecks is { Count: > 0 } &&
        DisabledOptionalChecks.Contains(id, StringComparer.OrdinalIgnoreCase);

    public static GuardianConfig CreateDefault() =>
        new(IpReputation: IpReputationConfig.CreateDefault());
}

public sealed record AccountSlotInfo(
    string Slot,
    bool IsCurrent,
    bool HasArchive,
    long ArchiveBytes,
    DateTimeOffset? LastArchivedAt)
{
    public string StatusText => IsCurrent
        ? "当前使用中"
        : HasArchive
            ? $"已归档 · {FormatBytes(ArchiveBytes)}"
            : "空槽位（首次切换将初始化）";

    public string TimestampText => LastArchivedAt.HasValue
        ? $"归档时间：{LastArchivedAt.Value.ToLocalTime():yyyy-MM-dd HH:mm}"
        : "尚未归档";

    public static string FormatBytes(long bytes)
    {
        if (bytes >= 1L << 40) return $"{bytes / (double)(1L << 40):0.#} TB";
        if (bytes >= 1L << 30) return $"{bytes / (double)(1L << 30):0.#} GB";
        if (bytes >= 1L << 20) return $"{bytes / (double)(1L << 20):0.#} MB";
        if (bytes >= 1L << 10) return $"{bytes / (double)(1L << 10):0.#} KB";
        return $"{bytes} B";
    }
}

public static class ProcessDiagnostics
{
    public static string FormatFailure(
        string fileName,
        int exitCode,
        string standardOutput,
        string standardError)
    {
        var detail = string.IsNullOrWhiteSpace(standardError)
            ? standardOutput.Trim()
            : standardError.Trim();

        return string.IsNullOrWhiteSpace(detail)
            ? $"{fileName} 退出码 {exitCode}，未返回错误信息"
            : $"{fileName} 退出码 {exitCode}：{detail}";
    }
}

public interface IEnvironmentProbe
{
    Task<NetworkSnapshot> CaptureNetworkAsync(
        GuardianConfig config,
        IReadOnlyList<ProcessInfo> protectedProcesses,
        bool full,
        CancellationToken cancellationToken);
}

public interface ISingleCheckProbe
{
    Task<NetworkSnapshot> CaptureSingleCheckAsync(
        NetworkSnapshot previous,
        string checkId,
        GuardianConfig config,
        IReadOnlyList<ProcessInfo> protectedProcesses,
        CancellationToken cancellationToken);
}

public interface IWebRtcBrowserProbe
{
    Task<WebRtcBrowserResult> ProbeAsync(
        IReadOnlyList<string> stunUrls,
        CancellationToken cancellationToken);
}

public interface IProcessInspector
{
    IReadOnlyList<ProcessInfo> FindClaudeProcessTree();
}

public interface IGuardianClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemGuardianClock : IGuardianClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
