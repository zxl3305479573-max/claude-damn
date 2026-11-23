namespace ClaudeDesktopGuardian.Core;

public enum CheckStatus
{
    Ok,
    Warn,
    Fail,
    Unknown
}

public sealed record CheckResult(
    string Id,
    string Title,
    CheckStatus Status,
    bool Blocking,
    string Detail,
    IReadOnlyDictionary<string, string> Evidence)
{
    public bool Passed => Status == CheckStatus.Ok || (Status == CheckStatus.Warn && !Blocking);
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
    WebRtcBrowserResult? BrowserWebRtc = null);

public sealed record GuardianReport(
    DateTimeOffset ObservedAt,
    IReadOnlyList<CheckResult> Checks,
    NetworkSnapshot Network,
    IReadOnlyList<ProcessInfo> ProtectedProcesses)
{
    public bool HasConfirmedWebRtcLeak =>
        Checks.Any(check =>
            check.Id == "webrtc" &&
            check.Status == CheckStatus.Fail);

    public bool CanRecover =>
        Checks.All(check => check.Status == CheckStatus.Ok || (check.Status == CheckStatus.Warn && !check.Blocking));

    public IReadOnlyList<CheckResult> BlockingFailures =>
        Checks.Where(check => check.Blocking && check.Status != CheckStatus.Ok).ToArray();

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
    IReadOnlyList<(string Host, int Port)>? StunServers = null)
{
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

    public IReadOnlyList<(string Host, int Port)> EffectiveStunServers =>
        StunServers is { Count: > 0 }
            ? StunServers
            : new[]
            {
                ("stun.cloudflare.com", 3478),
                ("stun.l.google.com", 19302),
                ("stun.miwifi.com", 3478)
            };

    public IReadOnlyList<string> EffectiveStunUrls =>
        EffectiveStunServers
            .Select(server => $"stun:{server.Host}:{server.Port}")
            .ToArray();
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

