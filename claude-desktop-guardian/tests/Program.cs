using ClaudeDesktopGuardian.Core;

var failures = new List<string>();

Assert(
    ProcessDiagnostics.FormatFailure("netsh.exe", 1, string.Empty, string.Empty)
        .Contains("退出码 1", StringComparison.Ordinal),
    "命令失败且没有输出时仍应提供退出码诊断",
    failures);
Assert(
    ProcessDiagnostics.FormatFailure("netsh.exe", 1, "标准输出", string.Empty)
        .Contains("标准输出", StringComparison.Ordinal),
    "命令标准错误为空时应回退显示标准输出",
    failures);

var probe = new FakeProbe();
var inspector = new FakeInspector();
var engine = new GuardianCheckEngine(probe, inspector, new FakeClock());
var config = new GuardianConfig(ExpectedExitIp: "203.0.113.10", ExpectedExitCountry: "US");
var report = await engine.RunAsync(config, true, CancellationToken.None);

Assert(report.Checks.Any(check => check.Id == "vpn-adapter" && check.Status == CheckStatus.Ok), "VPN 网卡检查应通过", failures);
Assert(report.Checks.Any(check => check.Id == "egress-ip" && check.Status == CheckStatus.Ok), "出口检查应通过", failures);
Assert(report.Checks.Any(check => check.Id == "webrtc" && check.Status == CheckStatus.Ok), "WebRTC 检查应通过", failures);
Assert(report.Checks.Any(check => check.Id == "ipv6" && check.Status == CheckStatus.Ok), "没有公网 IPv6 时检查应通过", failures);
Assert(
    report.Checks.Any(check => check.Id == "timezone" && check.Status == CheckStatus.Warn),
    "没有出口时区数据时应显示警告",
    failures);
Assert(report.CanRecover, "健康报告应允许恢复", failures);
Assert(!report.Checks.Any(check => check.Id == "claude-process" && check.Blocking), "Claude 进程状态不应阻断环境自检", failures);

var browserEngine = new GuardianCheckEngine(
    probe,
    inspector,
    new FakeBrowserProbe(new WebRtcBrowserResult(
        true,
        "complete",
        true,
        new[]
        {
            new WebRtcCandidate("192.168.1.10", "local", "IPv4"),
            new WebRtcCandidate("a1b2c3.local", "mdns", "mDNS")
        },
        "ICE 候选收集完成",
        Errors: new[]
        {
            new WebRtcIceError("stun:test.example:3478", 701, "STUN server could not be reached")
        })),
    new FakeClock());
var browserReport = await browserEngine.RunAsync(config, true, CancellationToken.None);
Assert(
    browserReport.Checks.Any(check =>
        check.Id == "webrtc" &&
        check.Status == CheckStatus.Unknown &&
        check.Blocking),
    "浏览器 ICE 报错时 WebRTC 应保持未验证并阻断",
    failures);
Assert(
    browserReport.Checks.Any(check =>
        check.Id == "webrtc" &&
        check.Detail.Contains("code=701", StringComparison.Ordinal) &&
        check.Detail.Contains("STUN server could not be reached", StringComparison.Ordinal)),
    "WebRTC 检查详情应包含浏览器 ICE 错误码和文本",
    failures);

var leakingBrowserEngine = new GuardianCheckEngine(
    probe,
    inspector,
    new FakeBrowserProbe(new WebRtcBrowserResult(
        true,
        "complete",
        true,
        new[]
        {
            new WebRtcCandidate("198.51.100.99", "public", "IPv4")
        },
        "ICE 候选收集完成")),
    new FakeClock());
var leakingBrowserReport = await leakingBrowserEngine.RunAsync(config, true, CancellationToken.None);
Assert(
    leakingBrowserReport.Checks.Any(check =>
        check.Id == "webrtc" &&
        check.Status == CheckStatus.Fail &&
        check.Detail.Contains("198.51.100.99", StringComparison.Ordinal)),
    "浏览器 ICE 出现非预期公网候选时应阻断",
    failures);
Assert(
    leakingBrowserReport.HasConfirmedWebRtcLeak,
    "检测到非预期公网候选时应标记为确认泄露",
    failures);

probe.HasIpv6 = true;
probe.ExitIpv6 = "2001:db8::10";
var allowedIpv6BrowserEngine = new GuardianCheckEngine(
    probe,
    inspector,
    new FakeBrowserProbe(new WebRtcBrowserResult(
        true,
        "complete",
        true,
        new[]
        {
            new WebRtcCandidate("2001:db8::10", "public", "IPv6")
        },
        "ICE 候选收集完成")),
    new FakeClock());
var allowedIpv6BrowserReport =
    await allowedIpv6BrowserEngine.RunAsync(config, true, CancellationToken.None);
Assert(
    allowedIpv6BrowserReport.Checks.Any(check =>
        check.Id == "webrtc" &&
        check.Status == CheckStatus.Ok),
    "浏览器 ICE 出现与 VPN IPv6 出口一致的公网候选时应通过",
    failures);
probe.HasIpv6 = false;
probe.ExitIpv6 = string.Empty;

var incompleteBrowserEngine = new GuardianCheckEngine(
    probe,
    inspector,
    new FakeBrowserProbe(new WebRtcBrowserResult(
        true,
        "incomplete",
        false,
        Array.Empty<WebRtcCandidate>(),
        "ICE 候选收集在超时前未完成")),
    new FakeClock());
var incompleteBrowserReport = await incompleteBrowserEngine.RunAsync(config, true, CancellationToken.None);
Assert(
    incompleteBrowserReport.Checks.Any(check =>
        check.Id == "webrtc" &&
        check.Status == CheckStatus.Unknown &&
        check.Blocking),
    "浏览器 ICE 未完成时应保持未验证并阻断",
    failures);
Assert(
    !incompleteBrowserReport.HasConfirmedWebRtcLeak,
    "浏览器 ICE 未完成时不应标记为确认泄露",
    failures);

var unknownExitProbe = new FakeProbe
{
    ExitIp = string.Empty,
    StunResults = new[]
    {
        new StunResult("stun.test", 3478, "ok", "198.51.100.44", "测试映射地址")
    }
};
var unknownExitReport = await new GuardianCheckEngine(
    unknownExitProbe,
    inspector,
    new FakeBrowserProbe(new WebRtcBrowserResult(
        true,
        "complete",
        true,
        new[] { new WebRtcCandidate("198.51.100.44", "public", "IPv4") },
        "ICE 候选收集完成")),
    new FakeClock()).RunAsync(
        new GuardianConfig(),
        true,
        CancellationToken.None);
Assert(
    unknownExitReport.Checks.Any(check =>
        check.Id == "webrtc" &&
        check.Status == CheckStatus.Unknown),
    "VPN 出口未知时不能把 STUN 地址直接判定为泄露",
    failures);
Assert(
    !unknownExitReport.HasConfirmedWebRtcLeak,
    "VPN 出口未知时不应标记为确认泄露",
    failures);

var unsupportedBrowserEngine = new GuardianCheckEngine(
    probe,
    inspector,
    new FakeBrowserProbe(WebRtcBrowserResult.Unsupported(
        "WebView2 Runtime 不可用或初始化失败")),
    new FakeClock());
var unsupportedBrowserReport =
    await unsupportedBrowserEngine.RunAsync(config, true, CancellationToken.None);
Assert(
    unsupportedBrowserReport.Checks.Any(check =>
        check.Id == "webrtc" &&
        check.Status == CheckStatus.Unknown &&
        check.Detail.Contains("WebView2 Runtime", StringComparison.Ordinal)),
    "WebView2 不可用时应显示具体原因并阻断",
    failures);

probe.StunResults = new[]
{
    new StunResult("stun.test", 3478, "unknown", string.Empty, "IPv4 STUN 超时")
};
var nativeUnknownWithBrowserPassEngine = new GuardianCheckEngine(
    probe,
    inspector,
    new FakeBrowserProbe(new WebRtcBrowserResult(
        true,
        "complete",
        true,
        Array.Empty<WebRtcCandidate>(),
        "ICE 候选收集完成")),
    new FakeClock());
var nativeUnknownWithBrowserPassReport =
    await nativeUnknownWithBrowserPassEngine.RunAsync(config, true, CancellationToken.None);
Assert(
    nativeUnknownWithBrowserPassReport.Checks.Any(check =>
        check.Id == "webrtc" &&
        check.Status == CheckStatus.Unknown &&
        check.Blocking),
    "原生 STUN 未验证时不能只凭浏览器无候选解除阻断",
    failures);
probe.StunResults = new[]
{
    new StunResult("stun.test", 3478, "ok", probe.ExitIp, "测试")
};

var statePath = Path.Combine(Path.GetTempPath(), "claude-desktop-guardian-state-" + Guid.NewGuid().ToString("N") + ".json");
try
{
    var store = new GuardianStateStore(statePath);
    store.Save(new GuardianState(true, "出口 IP 203.0.113.10 异常", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
    var saved = store.Load();
    Assert(saved.Blocked, "阻断状态应持久化", failures);
    Assert(saved.TripReason.Contains("<IP>", StringComparison.Ordinal), "状态文件应脱敏 IP", failures);

    store.Save(saved with
    {
        TimezoneOverrideActive = true,
        OriginalWindowsTimezone = "China Standard Time",
        AppliedWindowsTimezone = "Pacific Standard Time"
    });
    var timezoneState = store.Load();
    Assert(timezoneState.TimezoneOverrideActive, "时区临时切换状态应持久化", failures);
    Assert(
        timezoneState.OriginalWindowsTimezone == "China Standard Time",
        "原始 Windows 时区应持久化",
        failures);

    store.Save(timezoneState with { IgnoreWebRtc = true });
    Assert(store.Load().IgnoreWebRtc, "WebRTC 忽略设置应持久化", failures);

    store.Save(store.Load() with
    {
        Blocked = false,
        TripReason = "旧的断网原因",
        BlockedAt = DateTimeOffset.UtcNow
    });
    var cleared = store.Load();
    Assert(string.IsNullOrEmpty(cleared.TripReason), "解除阻断后不应保留旧断网原因", failures);
    Assert(cleared.BlockedAt is null, "解除阻断后不应保留阻断时间", failures);
}
finally
{
    File.Delete(statePath);
}

var tokenPath = Path.Combine(Path.GetTempPath(), "claude-desktop-guardian-token-" + Guid.NewGuid().ToString("N"));
try
{
    var tokenStore = new PipeTokenStore(tokenPath);
    var token = tokenStore.GetOrCreate();
    Assert(token.Length >= 32, "管理员助手令牌应随机生成", failures);
    Assert(token == tokenStore.GetOrCreate(), "管理员助手令牌应稳定复用", failures);
}
finally
{
    File.Delete(tokenPath);
}

probe.ExitIp = "198.51.100.5";
var failed = await engine.RunAsync(config, true, CancellationToken.None);
Assert(failed.BlockingFailures.Any(check => check.Id == "egress-ip"), "出口变化应触发阻断", failures);
Assert(!failed.CanRecover, "失败报告不得允许恢复", failures);

probe.HasIpv6 = true;
var ipv6Unavailable = await engine.RunAsync(config, true, CancellationToken.None);
Assert(
    ipv6Unavailable.Checks.Any(check =>
        check.Id == "ipv6" &&
        check.Status == CheckStatus.Unknown &&
        check.Blocking),
    "公网 IPv6 无法取得出口时应进入未验证阻断",
    failures);

probe.Ipv6ProbeDetail = "IPv6 连接已建立，但出口服务返回的地址不是 IPv6";
var ipv6WithoutPublicEgress = await engine.RunAsync(config, true, CancellationToken.None);
Assert(
    ipv6WithoutPublicEgress.Checks.Any(check =>
        check.Id == "ipv6" &&
        check.Status == CheckStatus.Ok &&
        check.Detail.Contains("未发现 IPv6 直连泄漏", StringComparison.Ordinal)),
    "VPN 接管 IPv6 但公网没有 IPv6 出口时不应阻断",
    failures);

Assert(
    WindowsTimezoneMapper.TryMap("America/Los_Angeles", out var pacific) &&
    pacific == "Pacific Standard Time",
    "IANA 时区应映射为 Windows 时区",
    failures);
Assert(
    !WindowsTimezoneMapper.TryMap("Invalid/Test", out _),
    "未知 IANA 时区不应映射成功",
    failures);

if (failures.Count > 0)
{
    foreach (var failure in failures)
    {
        Console.Error.WriteLine(failure);
    }
    return 1;
}

Console.WriteLine("Claude Desktop Guardian core tests passed.");
return 0;

static void Assert(bool condition, string message, ICollection<string> failures)
{
    if (!condition)
    {
        failures.Add(message);
    }
}

sealed class FakeClock : IGuardianClock
{
    public DateTimeOffset UtcNow => new(2026, 11, 22, 0, 0, 0, TimeSpan.Zero);
}

sealed class FakeInspector : IProcessInspector
{
    public IReadOnlyList<ProcessInfo> FindClaudeProcessTree() =>
        new[]
        {
            new ProcessInfo(10, 1, "Claude.exe", @"C:\Users\Test\AppData\Local\Programs\Claude\Claude.exe", "S-1-5-21-test")
        };
}

sealed class FakeProbe : IEnvironmentProbe
{
    public string ExitIp { get; set; } = "203.0.113.10";
    public string ExitIpv6 { get; set; } = string.Empty;
    public bool HasIpv6 { get; set; }
    public string Ipv6ProbeDetail { get; set; } = string.Empty;
    public IReadOnlyList<StunResult> StunResults { get; set; } =
        new[]
        {
            new StunResult("stun.test", 3478, "ok", "203.0.113.10", "测试")
        };

    public Task<NetworkSnapshot> CaptureNetworkAsync(
        GuardianConfig config,
        IReadOnlyList<ProcessInfo> protectedProcesses,
        bool full,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(new NetworkSnapshot(
            "VPN",
            "WireGuard",
            "198.18.0.2",
            "198.18.0.1",
            ExitIp,
            "US",
            ExitIpv6,
            string.Empty,
            new[] { "198.18.0.1" },
            StunResults,
            new[] { "203.0.113.10:443" },
            HasIpv6,
            new Dictionary<string, string> { ["api.anthropic.com"] = "200" },
            Ipv6ProbeDetail: Ipv6ProbeDetail));
    }
}

sealed class FakeBrowserProbe : IWebRtcBrowserProbe
{
    private readonly WebRtcBrowserResult _result;

    public FakeBrowserProbe(WebRtcBrowserResult result)
    {
        _result = result;
    }

    public Task<WebRtcBrowserResult> ProbeAsync(
        IReadOnlyList<string> stunUrls,
        CancellationToken cancellationToken) =>
        Task.FromResult(_result);
}

