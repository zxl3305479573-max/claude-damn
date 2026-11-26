using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Markup;
using System.Windows.Media;
using System.Xml.Linq;
using ClaudeDesktopGuardian.App;
using ClaudeDesktopGuardian.Core;
using ClaudeDesktopGuardian.Helper;

var failures = new List<string>();

// =========================================================================
// 1. Existing Baseline Tests (Preserved 100%)
// =========================================================================
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

// =========================================================================
// 2. GuardianConfigStore & ClashEndpointValidator Tests
// =========================================================================
Assert(ClashEndpointValidator.NormalizeLoopbackEndpoint("9090") == "127.0.0.1:9090", "纯端口号应规范为 127.0.0.1:9090", failures);
Assert(ClashEndpointValidator.NormalizeLoopbackEndpoint("0.0.0.0:9097") == "127.0.0.1:9097", "0.0.0.0 应规范为 127.0.0.1", failures);
Assert(ClashEndpointValidator.NormalizeLoopbackEndpoint("[::]:9091") == "127.0.0.1:9091", "[::] 应规范为 127.0.0.1", failures);
Assert(ClashEndpointValidator.NormalizeLoopbackEndpoint("http://localhost:9090") == "127.0.0.1:9090", "localhost 应规范为 127.0.0.1", failures);
Assert(ClashEndpointValidator.NormalizeLoopbackEndpoint("192.168.1.20:9090") is null, "非本机控制地址必须拒绝", failures);
Assert(ClashEndpointValidator.NormalizeLoopbackEndpoint("unix:///tmp/clash.sock") is null, "unix socket 路径应拒绝", failures);

var cfgPath = Path.Combine(Path.GetTempPath(), "cdg-config-" + Guid.NewGuid().ToString("N") + ".json");
try
{
    var cfgStore = new GuardianConfigStore(cfgPath);
    var savedCfg = cfgStore.Save(new GuardianConfig(
        ProxyClientMode: ProxyClientModes.ClashVerge,
        ExpectedExitCountry: "us",
        ExpectedExitIp: "203.0.113.10",
        ExpectedLocale: "en-US",
        FlClashController: "9090",
        ClashProxyGroup: "ClaudeProxy",
        WfpStrictEnabled: true,
        WfpAllowLoopback: true,
        AllowOptionalFailures: true,
        LoggingEnabled: true,
        DisabledOptionalChecks: new[] { GuardianCheckIds.Dns, GuardianCheckIds.EgressIp },
        IpReputation: new IpReputationConfig("https://rep.example.test/check", "secret-api-key-123", 30, 14)));
    Assert(savedCfg.ExpectedExitCountry == "US", "国家代码应规范为大写", failures);
    Assert(savedCfg.FlClashController == "127.0.0.1:9090", "FlClash 端口应规范化", failures);
    Assert(savedCfg.DisabledOptionalChecks is { Count: 1 } && savedCfg.DisabledOptionalChecks[0] == GuardianCheckIds.Dns, "核心硬检查 egress-ip 不得被加入禁用列表", failures);

    // Same URL with empty key preserves existing API key
    var preserved = cfgStore.Save(
        savedCfg with { IpReputation = new IpReputationConfig("https://rep.example.test/check", "", 20, 7) },
        preserveExistingApiKeyIfEmpty: true);
    Assert(preserved.IpReputation?.Key == "secret-api-key-123", "同 URL 留空密钥时应保留旧 API Key", failures);

    // Changed URL with empty key MUST NOT leak old API key to new host
    var changedUrl = cfgStore.Save(
        savedCfg with { IpReputation = new IpReputationConfig("https://other.example.test/check", "", 20, 7) },
        preserveExistingApiKeyIfEmpty: true);
    Assert(string.IsNullOrEmpty(changedUrl.IpReputation?.Key), "更换 URL 时不得沿用旧 API Key", failures);

    AssertThrows<ArgumentException>(() => cfgStore.Save(new GuardianConfig(
        IpReputation: new IpReputationConfig("http://insecure.example.test/api", "k", 25, 7))),
        "非 HTTPS 信誉源必须拒绝", failures);
    AssertThrows<ArgumentException>(() => cfgStore.Save(new GuardianConfig(FlClashController: "10.0.0.2:9090")),
        "远端 FlClash 控制地址必须拒绝", failures);
}
finally
{
    if (File.Exists(cfgPath)) File.Delete(cfgPath);
}

// =========================================================================
// 3. IpHistoryStore 48h Drift & CountryDefaults Tests
// =========================================================================
var histDir = Path.Combine(Path.GetTempPath(), "cdg-hist-" + Guid.NewGuid().ToString("N"));
try
{
    var hist = new IpHistoryStore(histDir);
    var t0 = new DateTimeOffset(2026, 11, 20, 0, 0, 0, TimeSpan.Zero);
    hist.RecordAndInspect("198.51.100.1", t0);
    hist.RecordAndInspect("198.51.100.2", t0.AddHours(10));
    var (prev, unique3) = hist.RecordAndInspect("198.51.100.3", t0.AddHours(20));
    Assert(prev == "198.51.100.2", "应记录上一次出口 IP", failures);
    Assert(unique3 == 3, "48 小时内 3 个不同出口 IP 应计数为 3", failures);

    // 60 hours later -> first two pruned, only 198.51.100.3 + new IP remain
    var (_, uniquePruned) = hist.RecordAndInspect("198.51.100.4", t0.AddHours(60));
    Assert(uniquePruned == 2, "超过 48 小时的旧记录应被自动裁剪", failures);
}
finally
{
    if (Directory.Exists(histDir)) Directory.Delete(histDir, true);
}

Assert(CountryDefaults.GetExpectedLocale("US") == "en-US", "US 默认 Locale 应为 en-US", failures);
Assert(CountryDefaults.GetExpectedLocale("JP") == "ja-JP", "JP 默认 Locale 应为 ja-JP", failures);
Assert(CountryDefaults.GetDefaultIanaTimezone("SG") == "Asia/Singapore", "SG 默认时区应为 Asia/Singapore", failures);

// =========================================================================
// 4. IpReputationService Normalization & Cache Isolation Tests
// =========================================================================
using (var repDoc = JsonDocument.Parse("""
{
  "risk": { "risk_score": 68, "risk_level": "high" },
  "flags": { "is_proxy": false, "is_vpn": true, "is_tor": false, "is_datacenter": true },
  "abuse": { "blacklist_count": 3 }
}
"""))
{
    var rec = IpReputationService.NormalizePayload(repDoc.RootElement, DateTimeOffset.UtcNow);
    Assert(rec.Score == 68 && rec.Level == "high", "信誉风险分与等级应正确归一", failures);
    Assert(rec.IsProxy == false && rec.IsVpn == true && rec.IsTor == false, "代理/VPN/Tor 标记应精确提取", failures);
    Assert(rec.IsHosting == true && rec.BlacklistCount == 3, "机房标记与黑名单数应精确提取", failures);
}

using (var partialDoc = JsonDocument.Parse("""{ "ip": "203.0.113.10" }"""))
{
    var rec = IpReputationService.NormalizePayload(partialDoc.RootElement, DateTimeOffset.UtcNow);
    Assert(rec.Score is null && rec.IsProxy is null && rec.IsHosting is null && rec.BlacklistCount is null,
        "缺失的信誉字段必须保持 null，不得伪装为 0 或 false", failures);
}

var repCachePath = Path.Combine(Path.GetTempPath(), "cdg-rep-" + Guid.NewGuid().ToString("N") + ".json");
try
{
    var mockHandler = new MockHttpHandler(req =>
    {
        var host = req.RequestUri?.Host ?? "";
        var hasKey = req.Headers.TryGetValues("X-API-Key", out var vals) && vals.Contains("k-test");
        var score = host.Contains("source-a", StringComparison.Ordinal) ? 10 : 85;
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($$"""{"fraud_score": {{score}}, "is_proxy": {{(hasKey ? "false" : "true")}}}""", Encoding.UTF8, "application/json")
        };
    });
    using var mockHttp = new HttpClient(mockHandler);
    var repSvc = new IpReputationService(mockHttp, repCachePath);
    var now = new DateTimeOffset(2026, 11, 22, 0, 0, 0, TimeSpan.Zero);

    var (recA, errA) = await repSvc.LookupAsync("203.0.113.10", new IpReputationConfig("https://source-a.test/ip", "k-test", 25, 7), now, CancellationToken.None);
    var (recB, errB) = await repSvc.LookupAsync("203.0.113.10", new IpReputationConfig("https://source-b.test/ip", "k-test", 25, 7), now, CancellationToken.None);
    Assert(string.IsNullOrEmpty(errA) && recA?.Score == 10 && recA.IsProxy == false, "信誉源 A 应通过 X-API-Key 请求并缓存", failures);
    Assert(string.IsNullOrEmpty(errB) && recB?.Score == 85, "同一 IP 在不同信誉源 URL 下必须独立缓存键", failures);
    Assert(mockHandler.RequestCount == 2, "前两次不同 URL 应各发一次请求", failures);

    var (recACached, _) = await repSvc.LookupAsync("203.0.113.10", new IpReputationConfig("https://source-a.test/ip", "k-test", 25, 7), now.AddDays(1), CancellationToken.None);
    Assert(recACached?.Score == 10 && mockHandler.RequestCount == 2, "TTL 有效期内应命中本地缓存", failures);
}
finally
{
    if (File.Exists(repCachePath)) File.Delete(repCachePath);
}

// =========================================================================
// 5. ClashInspector Pinned Rules & IPv6 Prefix Tests
// =========================================================================
var fullHeadRules = ClashInspector.PinnedDomains
    .Select(d => new ClashRuleEntry("DomainSuffix", d, "GLOBAL"))
    .Concat(ClashInspector.PinnedPorts.Select(p => new ClashRuleEntry("AND", $"((NETWORK,UDP),(DST-PORT,{p}))", "GLOBAL")))
    .ToArray();
Assert(ClashInspector.ArePinnedRulesLoaded(fullHeadRules), "完整 13 域名 + 3 STUN 端口置顶规则应判定已加载", failures);
Assert(!ClashInspector.ArePinnedRulesLoaded(fullHeadRules.Take(15).ToArray()), "缺少任意一条置顶规则应判定未加载", failures);

Assert(WindowsEnvironmentProbe.IsPublicOrNat64Ipv6Prefix(IPAddress.Parse("::").GetAddressBytes(), 0), "::/0 默认路由应识别为公网 IPv6", failures);
Assert(WindowsEnvironmentProbe.IsPublicOrNat64Ipv6Prefix(IPAddress.Parse("2000::").GetAddressBytes(), 3), "2000::/3 应识别为公网 IPv6", failures);
Assert(WindowsEnvironmentProbe.IsPublicOrNat64Ipv6Prefix(IPAddress.Parse("2606:4700::").GetAddressBytes(), 32), "全局单播前缀应识别为公网 IPv6", failures);
Assert(WindowsEnvironmentProbe.IsPublicOrNat64Ipv6Prefix(IPAddress.Parse("64:ff9b::").GetAddressBytes(), 96), "NAT64 64:ff9b::/96 应识别为泄漏路由", failures);
Assert(!WindowsEnvironmentProbe.IsPublicOrNat64Ipv6Prefix(IPAddress.Parse("fe80::").GetAddressBytes(), 10), "fe80::/10 链路本地不应误报", failures);
Assert(!WindowsEnvironmentProbe.IsPublicOrNat64Ipv6Prefix(IPAddress.Parse("fd00::").GetAddressBytes(), 8), "fd00::/8 ULA 不应误报", failures);
Assert(!WindowsEnvironmentProbe.IsPublicOrNat64Ipv6Prefix(IPAddress.Parse("::1").GetAddressBytes(), 128), "::1 回环不应误报", failures);

// =========================================================================
// 6. Upgraded CheckEngine Matrix Tests (WFP, Skip, Downgrade, Path Gate, DNS Fake-IP, Retest)
// =========================================================================
var extProbe = new ExtendedFakeProbe();
var extEngine = new GuardianCheckEngine(extProbe, inspector, new FakeClock());

// 6a. Strict Path Gate: zero leaks when proxy/TUN offline
extProbe.ProxyPathSkipped = true;
extProbe.AdapterName = string.Empty;
extProbe.ProxyClientAlive = false;
var gateReport = await extEngine.RunAsync(new GuardianConfig(), true, CancellationToken.None);
Assert(gateReport.Checks.Any(c => c.Id == GuardianCheckIds.EgressIp && c.Status == CheckStatus.Fail), "代理路径失效时出口 IP 必须失败", failures);
Assert(gateReport.Checks.Any(c => c.Id == GuardianCheckIds.ProxyClient && c.Status == CheckStatus.Fail), "代理客户端离线必须失败", failures);
Assert(!gateReport.CanRecover, "代理路径失效时不得允许恢复", failures);

// Restore healthy base state
extProbe.ResetHealthy();

// 6b. Non-VPN active IPv6 route table leak
extProbe.PublicIpv6Routes = new[] { "Ethernet" };
var v6LeakReport = await extEngine.RunAsync(new GuardianConfig(), true, CancellationToken.None);
Assert(v6LeakReport.Checks.Any(c => c.Id == GuardianCheckIds.Ipv6 && c.Status == CheckStatus.Fail && c.Blocking),
    "非 VPN 网卡存在公网 IPv6 路由时必须阻断失败", failures);
extProbe.PublicIpv6Routes = Array.Empty<string>();

// 6c. Fake-IP DNS tunnel mismatch
extProbe.AdapterIsFakeIp = true;
extProbe.ResolvedClaudeIps = new[] { "104.18.1.1" };
var dnsMismatch = await extEngine.RunAsync(new GuardianConfig(), true, CancellationToken.None);
Assert(dnsMismatch.Checks.Any(c => c.Id == GuardianCheckIds.Dns && c.Status == CheckStatus.Fail && c.Blocking),
    "Fake-IP TUN 在线但 claude.ai 未解析到 198.18.* 必须失败", failures);
extProbe.ResolvedClaudeIps = new[] { "198.18.0.42" };

// 6d. WFP Strict Mode vs Advisory
extProbe.WfpPolicyState = "off";
var wfpAdvisory = await extEngine.RunAsync(new GuardianConfig(WfpStrictEnabled: false), true, CancellationToken.None);
Assert(wfpAdvisory.Checks.Any(c => c.Id == GuardianCheckIds.WfpPolicy && c.Status == CheckStatus.Warn && !c.Blocking),
    "未开启 WFP 严格模式时 WFP 应为非阻断警告", failures);
Assert(wfpAdvisory.CanRecover, "WFP 严格模式关闭时不应阻断恢复", failures);

var wfpStrictOff = await extEngine.RunAsync(new GuardianConfig(WfpStrictEnabled: true), true, CancellationToken.None);
Assert(wfpStrictOff.Checks.Any(c => c.Id == GuardianCheckIds.WfpPolicy && c.Status == CheckStatus.Fail && c.Blocking),
    "开启 WFP 严格模式且未生效时必须阻断失败", failures);

extProbe.WfpPolicyState = "active";
var wfpStrictOn = await extEngine.RunAsync(new GuardianConfig(WfpStrictEnabled: true), true, CancellationToken.None);
Assert(wfpStrictOn.Checks.Any(c => c.Id == GuardianCheckIds.WfpPolicy && c.Status == CheckStatus.Ok),
    "WFP 生效时应通过", failures);

// 6e. Optional Check Disabling (Skip) & AllowOptionalFailures Downgrade
extProbe.ClashRulesStatus = "fail";
extProbe.ClashRulesDetail = "缺少置顶规则";
extProbe.IpReputation = new IpReputationRecord(DateTimeOffset.UtcNow, Score: 88, Level: "high", IsProxy: true, IsVpn: false, IsTor: false, IsHosting: true, BlacklistCount: 2);
var repCfg = new GuardianConfig(
    IpReputation: new IpReputationConfig("https://rep.test/api", "key", Threshold: 25, CacheDays: 7));
var dirtyRepReport = await extEngine.RunAsync(repCfg, true, CancellationToken.None);
Assert(dirtyRepReport.Checks.Any(c => c.Id == GuardianCheckIds.IpRepScore && c.Status == CheckStatus.Fail && c.Blocking), "高风险分应失败", failures);
Assert(dirtyRepReport.Checks.Any(c => c.Id == GuardianCheckIds.IpRepProxy && c.Status == CheckStatus.Fail && c.Blocking), "代理命中应失败", failures);
Assert(dirtyRepReport.Checks.Any(c => c.Id == GuardianCheckIds.IpRepBlacklist && c.Status == CheckStatus.Fail && c.Blocking), "黑名单命中应失败", failures);
Assert(dirtyRepReport.Checks.Any(c => c.Id == GuardianCheckIds.ClashRules && c.Status == CheckStatus.Fail && c.Blocking), "Clash 置顶缺失应失败", failures);

// Downgrade optional failures -> Warn (non-blocking), while hard exit CN STILL fails!
var downgradedReport = await extEngine.RunAsync(repCfg with { AllowOptionalFailures = true }, true, CancellationToken.None);
Assert(downgradedReport.Checks.Any(c => c.Id == GuardianCheckIds.ClashRules && c.Status == CheckStatus.Warn && !c.Blocking), "允许可选失败时 Clash 失败应降级为警告", failures);
Assert(downgradedReport.Checks.Any(c => c.Id == GuardianCheckIds.IpRepScore && c.Status == CheckStatus.Warn && !c.Blocking), "允许可选失败时高风险分应降级为警告", failures);
Assert(downgradedReport.CanRecover, "仅有可选检查降级警告时应允许恢复", failures);

extProbe.ExitCountry = "CN";
var hardCnStillBlocks = await extEngine.RunAsync(repCfg with { AllowOptionalFailures = true }, true, CancellationToken.None);
Assert(hardCnStillBlocks.Checks.Any(c => c.Id == GuardianCheckIds.EgressIp && c.Status == CheckStatus.Fail && c.Blocking),
    "即使允许可选失败降级，CN 直连出口仍必须硬阻断", failures);
extProbe.ExitCountry = "US";

// Disabling optional checks emits Skip (never Ok), and hard checks cannot be disabled
var skipReport = await extEngine.RunAsync(
    repCfg with { DisabledOptionalChecks = new[] { GuardianCheckIds.ClashRules, GuardianCheckIds.IpRepScore, GuardianCheckIds.IpRepProxy, GuardianCheckIds.IpRepBlacklist, GuardianCheckIds.EgressIp } },
    true,
    CancellationToken.None);
Assert(skipReport.Checks.Any(c => c.Id == GuardianCheckIds.ClashRules && c.Status == CheckStatus.Skip && !c.Blocking), "禁用的可选检查应标为 Skip", failures);
Assert(skipReport.Checks.Any(c => c.Id == GuardianCheckIds.EgressIp && c.Status == CheckStatus.Ok), "硬检查 egress-ip 不应被跳过", failures);

// 6f. 48h Drift Warning + RunSingleCheckAsync
extProbe.IpDriftCount48h = 3;
var driftReport = await extEngine.RunAsync(new GuardianConfig(), true, CancellationToken.None);
Assert(driftReport.Checks.Any(c => c.Id == GuardianCheckIds.IpConsistency && c.Status == CheckStatus.Warn && c.Detail.Contains("48h", StringComparison.Ordinal)),
    "48h 内出口 IP 漂移 >= 3 个应发出警告", failures);

extProbe.ClashRulesStatus = "ok";
extProbe.ClashRulesDetail = "已加载全部 16 条规则";
var singleRetest = await extEngine.RunSingleCheckAsync(dirtyRepReport, GuardianCheckIds.ClashRules, repCfg, CancellationToken.None);
Assert(singleRetest.Checks.Any(c => c.Id == GuardianCheckIds.ClashRules && c.Status == CheckStatus.Ok),
    "单项复检应更新目标检查项为 Ok", failures);

// =========================================================================
// 7. Transactional Multi-Account Switching & .csnap Encrypted Snapshot Tests
// =========================================================================
var acctRoot = Path.Combine(Path.GetTempPath(), "cdg-acct-test-" + Guid.NewGuid().ToString("N"));
try
{
    var baseDir = Path.Combine(acctRoot, "guardian");
    var claudeData = Path.Combine(acctRoot, "ClaudeData");
    Directory.CreateDirectory(claudeData);
    File.WriteAllText(Path.Combine(claudeData, "Cookies"), "slot-a-cookie-secret");
    File.WriteAllText(Path.Combine(claudeData, "claude_desktop_config.json"), "{\"mcpServers\":{}}");

    var mgr = new AccountSlotManager(baseDir, claudeData, () => true, () => true, () => true);
    mgr.SaveKeepPathsText("# Shared config\nclaude_desktop_config.json\n../escape.txt\nC:\\Windows\\win.ini\n");

    // Fail-Closed gate rejects switching when unhealthy
    var blockedSwitch = mgr.SwitchToSlot("B", environmentHealthy: false, "IPv6 泄漏", launchAfterSwitch: false);
    Assert(!blockedSwitch.Success && blockedSwitch.Message.Contains("Fail-Closed", StringComparison.Ordinal),
        "环境异常时必须拒绝切换账号", failures);

    // Healthy switch: adopts existing data as A, switches to empty B, preserves shared file
    var switchToB = mgr.SwitchToSlot("B", environmentHealthy: true, null, launchAfterSwitch: false);
    Assert(switchToB.Success, "健康环境下首次切换到 B 应成功：" + switchToB.Message, failures);
    Assert(mgr.GetCurrentSlot() == "B", "当前槽位应更新为 B", failures);
    Assert(!File.Exists(Path.Combine(claudeData, "Cookies")), "切换到空槽位 B 后不应残留 A 的 Cookies", failures);
    Assert(File.Exists(Path.Combine(claudeData, "claude_desktop_config.json")), "keep-in-workspace.txt 共享文件应保留", failures);

    // Add slot B exclusive file and switch back to A
    File.WriteAllText(Path.Combine(claudeData, "slot-b-marker.txt"), "hello-from-B");
    var switchBackA = mgr.SwitchToSlot("A", environmentHealthy: true, null, launchAfterSwitch: false);
    Assert(switchBackA.Success, "切回 A 应成功：" + switchBackA.Message, failures);
    Assert(File.ReadAllText(Path.Combine(claudeData, "Cookies")) == "slot-a-cookie-secret", "切回 A 后原数据应完整恢复", failures);
    Assert(!File.Exists(Path.Combine(claudeData, "slot-b-marker.txt")), "切回 A 后不应出现 B 的文件", failures);

    // Export guards
    var snapPath = Path.Combine(acctRoot, "slot-b.csnap");
    Assert(!mgr.ExportEncryptedSnapshot("A", snapPath, "StrongPass!2026").Success, "活跃槽位 A 不应允许直接导出", failures);
    Assert(!mgr.ExportEncryptedSnapshot("B", snapPath, "short").Success, "少于 8 位密码必须拒绝导出", failures);

    var exportB = mgr.ExportEncryptedSnapshot("B", snapPath, "StrongPass!2026");
    Assert(exportB.Success && File.Exists(snapPath), "非活跃槽位 B 应成功导出 .csnap：" + exportB.Message, failures);

    var headerBytes = File.ReadAllBytes(snapPath)[..8];
    Assert(Encoding.ASCII.GetString(headerBytes) == "CSNAP001", "快照文件头必须兼容 CSNAP001 魔数", failures);

    // Tamper detection & wrong password
    var tamperedPath = Path.Combine(acctRoot, "tampered.csnap");
    var rawBytes = File.ReadAllBytes(snapPath);
    rawBytes[^5] ^= 0xFF;
    File.WriteAllBytes(tamperedPath, rawBytes);
    var tempPlain = Path.Combine(acctRoot, "plain.zip");
    Assert(!EncryptedSnapshotService.UnprotectFile(tamperedPath, tempPlain, "StrongPass!2026"), "篡改密文后 HMAC 校验必须拒绝", failures);
    Assert(!EncryptedSnapshotService.UnprotectFile(snapPath, tempPlain, "WrongPassword!"), "错误密码必须解密失败", failures);

    // Import into mismatched slot C rejected
    Assert(!mgr.ImportEncryptedSnapshot(snapPath, "C", "StrongPass!2026").Success, "槽位不匹配的快照导入必须拒绝", failures);

    // Import into clean second manager slot B & verify integrity
    var baseDir2 = Path.Combine(acctRoot, "guardian2");
    var claudeData2 = Path.Combine(acctRoot, "ClaudeData2");
    var mgr2 = new AccountSlotManager(baseDir2, claudeData2, () => true, () => true, () => true);
    var importB = mgr2.ImportEncryptedSnapshot(snapPath, "B", "StrongPass!2026");
    Assert(importB.Success, "空槽位 B 应成功导入 .csnap：" + importB.Message, failures);
    var activateB = mgr2.SwitchToSlot("B", environmentHealthy: true, null, launchAfterSwitch: false);
    Assert(activateB.Success && File.ReadAllText(Path.Combine(claudeData2, "slot-b-marker.txt")) == "hello-from-B",
        "导入后切换到 B 应完整还原快照内容", failures);
}
finally
{
    if (Directory.Exists(acctRoot)) Directory.Delete(acctRoot, true);
}

// =========================================================================
// 8. Sanitized Logger Rotation & Redacted Diagnostics Zip Tests
// =========================================================================
var diagRoot = Path.Combine(Path.GetTempPath(), "cdg-diag-test-" + Guid.NewGuid().ToString("N"));
try
{
    var logPath = Path.Combine(diagRoot, "guardian.log");
    var logger = new GuardianLogger(logPath);
    logger.LogAction("full-check", "ok", 123, driftReport.Checks, enabled: true);
    var tail = logger.ReadSanitizedTail();
    Assert(tail.Count == 1 && tail[0].Contains("action=full-check", StringComparison.Ordinal), "脱敏日志应记录标准结构行", failures);

    var zipPath = Path.Combine(diagRoot, "diag.zip");
    DiagnosticsExporter.ExportZip(
        zipPath,
        new GuardianConfig(
            ExpectedExitIp: "203.0.113.77",
            IpReputation: new IpReputationConfig("https://rep.secret.example/v1", "SUPER-SECRET-TOKEN-999", 25, 7)),
        new GuardianState(false, string.Empty, null, DateTimeOffset.UtcNow),
        driftReport,
        logger);

    Assert(File.Exists(zipPath), "诊断包 zip 应成功生成", failures);
    using var zip = ZipFile.OpenRead(zipPath);
    var entryNames = zip.Entries.Select(e => e.FullName).ToHashSet(StringComparer.OrdinalIgnoreCase);
    Assert(entryNames.Contains("environment.json") && entryNames.Contains("recent-status.json") &&
           entryNames.Contains("config-redacted.json") && entryNames.Contains("guardian.log"),
        "诊断包应包含全部 4 个标准文件", failures);
    foreach (var entry in zip.Entries)
    {
        using var sr = new StreamReader(entry.Open(), Encoding.UTF8);
        var content = sr.ReadToEnd();
        Assert(!content.Contains("203.0.113.77", StringComparison.Ordinal), $"诊断包 {entry.FullName} 不得泄漏明文期望 IP", failures);
        Assert(!content.Contains("SUPER-SECRET-TOKEN-999", StringComparison.Ordinal), $"诊断包 {entry.FullName} 不得泄漏 API Key", failures);
    }
}
finally
{
    if (Directory.Exists(diagRoot)) Directory.Delete(diagRoot, true);
}

// =========================================================================
// 9. Standalone Proxy Diagnostics Configuration Validation (Offline)
// =========================================================================
var badProxy1 = await ProxyDiagnosticsRunner.RunAsync("", CancellationToken.None);
var badProxy2 = await ProxyDiagnosticsRunner.RunAsync("ftp://127.0.0.1:21", CancellationToken.None);
var badProxy3 = await ProxyDiagnosticsRunner.RunAsync("http://127.0.0.1:7890/extra", CancellationToken.None);
var badProxy4 = await ProxyDiagnosticsRunner.RunAsync("http://127.0.0.1", CancellationToken.None);
Assert(badProxy1.State == "configuration_error" &&
       badProxy2.State == "configuration_error" &&
       badProxy3.State == "configuration_error" &&
       badProxy4.State == "configuration_error",
    "非法代理 URL 必须返回 configuration_error 而不发起外网探测", failures);

// =========================================================================
// 10. ProtectionPolicyEvaluator Fail-Closed State Machine Tests
// =========================================================================
extProbe.ResetHealthy();
var smHealthyReport = await extEngine.RunAsync(new GuardianConfig(), true, CancellationToken.None);
extProbe.ExitCountry = "CN";
var smFailReport = await extEngine.RunAsync(new GuardianConfig(), true, CancellationToken.None);
extProbe.ResetHealthy();

var decTrip = ProtectionPolicyEvaluator.Evaluate(smFailReport, currentlyBlocked: false, ignoreWebRtc: false, allowClearBlock: false);
Assert(decTrip.Action == ProtectionAction.ApplyBlockAndTerminate, "未阻断且 Claude 运行中出现硬失败应立即阻断并终止", failures);

var smNoClaudeFail = smFailReport with { ProtectedProcesses = Array.Empty<ProcessInfo>() };
var decStayNoClaude = ProtectionPolicyEvaluator.Evaluate(smNoClaudeFail, currentlyBlocked: true, ignoreWebRtc: false, allowClearBlock: false);
Assert(decStayNoClaude.Action == ProtectionAction.StayBlocked, "已阻断时 Claude 退出不得自动解除阻断", failures);

var decStayLightTick = ProtectionPolicyEvaluator.Evaluate(smHealthyReport, currentlyBlocked: true, ignoreWebRtc: false, allowClearBlock: false);
Assert(decStayLightTick.Action == ProtectionAction.StayBlocked, "已阻断时轻量巡检未显式点击恢复不得自动解除阻断", failures);

var decEnforceRelaunch = ProtectionPolicyEvaluator.Evaluate(smFailReport, currentlyBlocked: true, ignoreWebRtc: false, allowClearBlock: false);
Assert(decEnforceRelaunch.Action == ProtectionAction.EnforceExistingBlockTerminateOnly, "已阻断期间 Claude 重新启动且仍异常应再次终止", failures);

var decDenyRecoverNoClaude = ProtectionPolicyEvaluator.Evaluate(smNoClaudeFail, currentlyBlocked: true, ignoreWebRtc: false, allowClearBlock: true);
Assert(decDenyRecoverNoClaude.Action == ProtectionAction.StayBlocked, "仍有阻断失败且无 Claude 时点击恢复必须保持阻断", failures);

var decDenyRecoverWithClaude = ProtectionPolicyEvaluator.Evaluate(smFailReport, currentlyBlocked: true, ignoreWebRtc: false, allowClearBlock: true);
Assert(decDenyRecoverWithClaude.Action == ProtectionAction.EnforceExistingBlockTerminateOnly, "仍有阻断失败且 Claude 运行时点击恢复必须维持阻断并终止", failures);

var decAllowRecover = ProtectionPolicyEvaluator.Evaluate(smHealthyReport, currentlyBlocked: true, ignoreWebRtc: false, allowClearBlock: true);
Assert(decAllowRecover.Action == ProtectionAction.ClearBlock, "显式恢复且无阻断失败时应允许解除阻断", failures);

// Confirmed WebRTC leak NEVER downgraded by IgnoreWebRtc or AllowOptionalFailures
var leakingWithDowngrade = await leakingBrowserEngine.RunAsync(
    config with { AllowOptionalFailures = true },
    true,
    CancellationToken.None);
Assert(
    leakingWithDowngrade.Checks.Any(c => c.Id == GuardianCheckIds.WebRtc && c.Status == CheckStatus.Fail && c.Blocking),
    "确认 WebRTC 公网泄露不得因 AllowOptionalFailures 降级为警告",
    failures);
var decWebRtcLeakIgnored = ProtectionPolicyEvaluator.Evaluate(leakingWithDowngrade, currentlyBlocked: false, ignoreWebRtc: true, allowClearBlock: false);
Assert(
    decWebRtcLeakIgnored.Action == ProtectionAction.ApplyBlockAndTerminate,
    "即使开启忽略 WebRTC 阻断，确认非 VPN 公网泄露仍必须立即阻断",
    failures);
Assert(
    ProtectionPolicyEvaluator.GetEffectiveBlockingFailures(incompleteBrowserReport, ignoreWebRtc: false).All(c => c.Id != GuardianCheckIds.WebRtc),
    "WebRTC Unknown 不得触发自动阻断",
    failures);
Assert(
    !ProtectionPolicyEvaluator.HasEffectiveUiStatus(incompleteBrowserReport, CheckStatus.Unknown, ignoreWebRtc: true) &&
    ProtectionPolicyEvaluator.HasEffectiveUiStatus(incompleteBrowserReport, CheckStatus.Unknown, ignoreWebRtc: false),
    "忽略 WebRTC 阻断开关应仅影响 WebRTC Unknown 的主状态显示",
    failures);

// =========================================================================
// 11. Light Tick 23-Check Retention, Helper/Firewall/ActiveConnections,
//     WebRTC Reject Policy & True ISingleCheckProbe Retest
// =========================================================================
extProbe.ResetHealthy();
var full23 = await extEngine.RunAsync(new GuardianConfig(), full: true, CancellationToken.None);
var light23 = await extEngine.RunAsync(new GuardianConfig(), full: false, CancellationToken.None);
Assert(full23.Checks.Count == 23, $"完整检查应输出 23 项（实际 {full23.Checks.Count}）", failures);
Assert(light23.Checks.Count == 23, $"完成首次完整检查后，轻量刷新仍应保留 23 项（实际 {light23.Checks.Count}）", failures);
Assert(light23.Checks.Any(c => c.Id == GuardianCheckIds.ClashRules) &&
       light23.Checks.Any(c => c.Id == GuardianCheckIds.ClaudeDomains) &&
       light23.Checks.Any(c => c.Id == GuardianCheckIds.IpRepScore),
    "轻量刷新不得丢失 16-23 项扩展检查", failures);

// Helper offline -> both helper-service and firewall-readiness fail & block
extProbe.HelperAlive = false;
var helperDownReport = await extEngine.RunAsync(new GuardianConfig(), full: false, CancellationToken.None);
Assert(helperDownReport.Checks.Any(c => c.Id == GuardianCheckIds.HelperService && c.Status == CheckStatus.Fail && c.Blocking),
    "管理员助手离线时 helper-service 必须硬失败", failures);
Assert(helperDownReport.Checks.Any(c => c.Id == GuardianCheckIds.FirewallReadiness && c.Status == CheckStatus.Fail && c.Blocking),
    "管理员助手离线时 firewall-readiness 必须硬失败", failures);

// Helper alive but Firewall API unhealthy -> firewall-readiness fails
extProbe.HelperAlive = true;
extProbe.FirewallApiOk = false;
var fwBadReport = await extEngine.RunAsync(new GuardianConfig(), full: false, CancellationToken.None);
Assert(fwBadReport.Checks.Any(c => c.Id == GuardianCheckIds.HelperService && c.Status == CheckStatus.Ok),
    "管理员助手在线时 helper-service 应通过", failures);
Assert(fwBadReport.Checks.Any(c => c.Id == GuardianCheckIds.FirewallReadiness && c.Status == CheckStatus.Fail && c.Blocking),
    "防火墙状态读取失败时 firewall-readiness 必须硬失败", failures);
extProbe.FirewallApiOk = true;

// Active connections policy: 443 + loopback OK, non-443 remote Warn (Blocking only with BlockOnWarning)
extProbe.ActiveConnections = new[] { "203.0.113.10:443", "127.0.0.1:7890", "[::1]:10808" };
var connOkReport = await extEngine.RunAsync(new GuardianConfig(), full: false, CancellationToken.None);
Assert(connOkReport.Checks.Any(c => c.Id == GuardianCheckIds.ActiveConnections && c.Status == CheckStatus.Ok),
    "TCP 443 与本机回环连接应判定为正常", failures);

extProbe.ActiveConnections = new[] { "198.51.100.5:8443" };
var connWarnReport = await extEngine.RunAsync(new GuardianConfig(BlockOnWarning: false), full: false, CancellationToken.None);
Assert(connWarnReport.Checks.Any(c => c.Id == GuardianCheckIds.ActiveConnections && c.Status == CheckStatus.Warn && !c.Blocking),
    "非 443 远端端口应给出告警", failures);
var connBlockReport = await extEngine.RunAsync(new GuardianConfig(BlockOnWarning: true), full: false, CancellationToken.None);
Assert(connBlockReport.Checks.Any(c => c.Id == GuardianCheckIds.ActiveConnections && c.Status == CheckStatus.Warn && c.Blocking),
    "开启 BlockOnWarning 时非 443 远端端口应标记阻断", failures);
extProbe.ActiveConnections = Array.Empty<string>();

// WebRTC reject policy: verified Clash REJECT rules + silent STUN + clean browser ICE -> Ok; proxy policy -> Unknown
extProbe.ResetHealthy();
extProbe.StunResultsOverride = new[] { new StunResult("stun.cloudflare.com", 3478, "unknown", string.Empty, "UDP timeout") };
extProbe.ClashRulesLoadedOverride = true;
var cleanBrowserProbe = new CountingBrowserProbe(new WebRtcBrowserResult(
    true,
    "complete",
    true,
    new[] { new WebRtcCandidate("a1b2c3.local", "mdns", "mDNS") },
    "ICE 候选收集完成"));
var rejectEngine = new GuardianCheckEngine(extProbe, inspector, cleanBrowserProbe, new FakeClock());
var rejectOkReport = await rejectEngine.RunAsync(new GuardianConfig(WebRtcPolicy: WebRtcPolicies.Reject), true, CancellationToken.None);
Assert(rejectOkReport.Checks.Any(c => c.Id == GuardianCheckIds.WebRtc && c.Status == CheckStatus.Ok),
    "WebRTC reject 策略且 Clash 规则已核验、浏览器无公网候选时，STUN 全静默应判通过", failures);

var proxySilentReport = await rejectEngine.RunAsync(new GuardianConfig(WebRtcPolicy: WebRtcPolicies.Proxy), true, CancellationToken.None);
Assert(proxySilentReport.Checks.Any(c => c.Id == GuardianCheckIds.WebRtc && c.Status == CheckStatus.Unknown),
    "WebRTC proxy 策略下 STUN 全静默仍必须保持 Unknown，不得假装通过", failures);

extProbe.ClashRulesLoadedOverride = false;
var rejectUnverifiedReport = await rejectEngine.RunAsync(new GuardianConfig(WebRtcPolicy: WebRtcPolicies.Reject), true, CancellationToken.None);
Assert(rejectUnverifiedReport.Checks.Any(c => c.Id == GuardianCheckIds.WebRtc && c.Status == CheckStatus.Unknown),
    "WebRTC reject 策略但 Clash 置顶规则未核验时，STUN 静默不得判通过", failures);
extProbe.ResetHealthy();

// True ISingleCheckProbe retest: skips unrelated full capture and browser probe
var singleStubProbe = new CountingSingleCheckProbe();
var singleBrowserProbe = new CountingBrowserProbe(new WebRtcBrowserResult(true, "complete", true, Array.Empty<WebRtcCandidate>(), "ICE 完成"));
var singleEngine = new GuardianCheckEngine(singleStubProbe, inspector, singleBrowserProbe, new FakeClock());
var singleBase = await singleEngine.RunAsync(new GuardianConfig(), full: true, CancellationToken.None);
Assert(singleStubProbe.FullCaptureCount == 1 && singleBrowserProbe.ProbeCount == 1, "首次完整检查应各触发一次全量与浏览器探测", failures);

singleStubProbe.NextDnsIps = new[] { "198.18.0.99" };
var dnsRetest = await singleEngine.RunSingleCheckAsync(singleBase, GuardianCheckIds.Dns, new GuardianConfig(), CancellationToken.None);
Assert(singleStubProbe.FullCaptureCount == 1 && singleStubProbe.SingleCaptureCount == 1 && singleStubProbe.LastSingleCheckId == GuardianCheckIds.Dns,
    "单项复检 DNS 应仅调用 CaptureSingleCheckAsync 而不触发全量探测", failures);
Assert(singleBrowserProbe.ProbeCount == 1, "单项复检 DNS 不得触发浏览器 WebRTC 探测", failures);
Assert(dnsRetest.Checks.Any(c => c.Id == GuardianCheckIds.Dns && c.Detail.Contains("单项复检完成", StringComparison.Ordinal)),
    "单项复检 DNS 应更新目标项详情", failures);

_ = await singleEngine.RunSingleCheckAsync(dnsRetest, GuardianCheckIds.WebRtc, new GuardianConfig(), CancellationToken.None);
Assert(singleStubProbe.FullCaptureCount == 1 && singleStubProbe.SingleCaptureCount == 2 && singleBrowserProbe.ProbeCount == 2,
    "单项复检 WebRTC 应仅通过单检路径并触发一次浏览器 ICE 探测", failures);

// =========================================================================
// 12. IpReputationService.BuildRequestUrl & WebRtcPolicy Config/Diagnostics
// =========================================================================
Assert(IpReputationService.BuildRequestUrl("https://rep.test/v1/{ip}/score", "203.0.113.10") == "https://rep.test/v1/203.0.113.10/score",
    "{ip} 占位符应精确替换", failures);
Assert(IpReputationService.BuildRequestUrl("https://rep.test/v1?addr={{ip}}&fmt=json", "203.0.113.10") == "https://rep.test/v1?addr=203.0.113.10&fmt=json",
    "{{ip}} 占位符应精确替换", failures);
Assert(IpReputationService.BuildRequestUrl("https://rep.test/check", "203.0.113.10") == "https://rep.test/check?ip=203.0.113.10",
    "无占位符时应追加 ?ip=", failures);
Assert(IpReputationService.BuildRequestUrl("https://rep.test/check?a=1", "203.0.113.10") == "https://rep.test/check?a=1&ip=203.0.113.10",
    "已有查询参数时应追加 &ip=", failures);
Assert(IpReputationService.BuildRequestUrl("http://rep.test/{ip}", "203.0.113.10") is null,
    "非 HTTPS 模板必须拒绝", failures);
Assert(IpReputationService.BuildRequestUrl("https://{ip}.evil.test/api", "203.0.113.10") is null,
    "替换后改变主机名的模板必须拒绝", failures);

var policyCfgPath = Path.Combine(Path.GetTempPath(), "cdg-policy-" + Guid.NewGuid().ToString("N") + ".json");
var policyZipPath = Path.Combine(Path.GetTempPath(), "cdg-policy-" + Guid.NewGuid().ToString("N") + ".zip");
try
{
    var pStore = new GuardianConfigStore(policyCfgPath);
    var savedReject = pStore.Save(new GuardianConfig(
        WebRtcPolicy: WebRtcPolicies.Reject,
        IpReputation: new IpReputationConfig("https://rep.test/v1/{ip}", "KEY-XYZ", 25, 7)));
    Assert(savedReject.WebRtcPolicy == WebRtcPolicies.Reject, "WebRTC reject 策略应持久化", failures);
    Assert(savedReject.IpReputation?.Url == "https://rep.test/v1/{ip}", "包含 {ip} 占位符的 HTTPS 信誉 URL 应通过校验", failures);

    AssertThrows<ArgumentException>(
        () => pStore.Save(new GuardianConfig(WebRtcPolicy: "bogus")),
        "保存非法 WebRTC 策略必须拒绝并抛出 ArgumentException",
        failures);
    Assert(WebRtcPolicies.Normalize("bogus") == WebRtcPolicies.Proxy, "WebRtcPolicies.Normalize 对非法值应回退为 proxy", failures);

    DiagnosticsExporter.ExportZip(
        policyZipPath,
        savedReject,
        new GuardianState(false, string.Empty, null, DateTimeOffset.UtcNow),
        full23,
        new GuardianLogger(Path.Combine(Path.GetTempPath(), "cdg-nolog-" + Guid.NewGuid().ToString("N") + ".log")));
    using var pZip = ZipFile.OpenRead(policyZipPath);
    using var pSr = new StreamReader(pZip.GetEntry("config-redacted.json")!.Open(), Encoding.UTF8);
    var redactedJson = pSr.ReadToEnd();
    Assert(redactedJson.Contains("\"webrtc_policy\": \"reject\"", StringComparison.Ordinal) &&
           !redactedJson.Contains("KEY-XYZ", StringComparison.Ordinal),
        "诊断包应记录 webrtc_policy 且不泄漏密钥", failures);
}
finally
{
    if (File.Exists(policyCfgPath)) File.Delete(policyCfgPath);
    if (File.Exists(policyZipPath)) File.Delete(policyZipPath);
}

// =========================================================================
// 13. ClashInspector Proxy Group, Script.js Wrapper, Policy Check & Merge Cleanup
// =========================================================================
var clashDir = Path.Combine(Path.GetTempPath(), "cdg-clash-" + Guid.NewGuid().ToString("N"));
try
{
    Directory.CreateDirectory(Path.Combine(clashDir, "profiles"));
    File.WriteAllText(
        Path.Combine(clashDir, "clash-verge.yaml"),
        """
        port: 7897
        proxy-groups:
          - name: AutoFast
            type: url-test
          - name: "MySelectGroup"
            type: select
        """,
        new UTF8Encoding(false));
    Assert(ClashInspector.DetectDefaultProxyGroup(clashDir) == "MySelectGroup",
        "应从 clash-verge.yaml 提取首个 type: select 代理组", failures);

    // Fresh Script.js write + idempotent repeat
    var w1 = ClashInspector.WriteClashVergePinnedRules("MySelectGroup", WebRtcPolicies.Proxy, clashDir);
    var scriptPath = Path.Combine(clashDir, "profiles", "Script.js");
    Assert(w1.Success && w1.Changed && File.Exists(scriptPath), "新建 Script.js 应成功：" + w1.Message, failures);
    var s1 = File.ReadAllText(scriptPath, Encoding.UTF8);
    Assert(s1.Contains("AND,((NETWORK,UDP),(DST-PORT,3478)),MySelectGroup", StringComparison.Ordinal),
        "proxy 策略下 STUN 规则应仅匹配 UDP 并指向代理组", failures);
    var w2 = ClashInspector.WriteClashVergePinnedRules("MySelectGroup", WebRtcPolicies.Proxy, clashDir);
    Assert(w2.Success && !w2.Changed, "重复写入相同配置应幂等无变更", failures);

    // Existing custom main wrapper + reject policy
    File.WriteAllText(
        scriptPath,
        """
        function main(config, profileName) {
          config.rules = (config.rules || []).concat(["MATCH,DIRECT"]);
          return config;
        }
        """,
        new UTF8Encoding(false));
    var w3 = ClashInspector.WriteClashVergePinnedRules("MySelectGroup", WebRtcPolicies.Reject, clashDir);
    Assert(w3.Success && w3.Changed && !string.IsNullOrEmpty(w3.BackupPath) && File.Exists(w3.BackupPath),
        "改写已有 Script.js 应成功并生成备份：" + w3.Message, failures);
    var s3 = File.ReadAllText(scriptPath, Encoding.UTF8);
    Assert(s3.Contains("const __cdgOrigMain = main;", StringComparison.Ordinal) &&
           s3.Contains("main = function (config, profileName)", StringComparison.Ordinal) &&
           s3.Contains("AND,((NETWORK,UDP),(DST-PORT,19302)),REJECT", StringComparison.Ordinal) &&
           s3.Contains("MATCH,DIRECT", StringComparison.Ordinal),
        "包装已有 main 时应保留原函数逻辑并使用非提升赋值与 REJECT 策略", failures);
    var w4 = ClashInspector.WriteClashVergePinnedRules("MySelectGroup", WebRtcPolicies.Reject, clashDir);
    Assert(w4.Success && !w4.Changed, "再次写入已有包装脚本应幂等无变更", failures);

    // ArePinnedRulesLoaded target verification under proxy vs reject
    var rejectHeadRules = ClashInspector.PinnedDomains
        .Select(d => new ClashRuleEntry("DomainSuffix", d, "MySelectGroup"))
        .Concat(ClashInspector.PinnedPorts.Select(p => new ClashRuleEntry("AND", $"((NETWORK,UDP),(DST-PORT,{p}))", "REJECT")))
        .ToArray();
    Assert(ClashInspector.ArePinnedRulesLoaded(rejectHeadRules, WebRtcPolicies.Reject),
        "reject 策略下 STUN 指向 REJECT 应判定已加载", failures);
    Assert(!ClashInspector.ArePinnedRulesLoaded(fullHeadRules, WebRtcPolicies.Reject),
        "reject 策略下 STUN 指向代理组不得判定为 reject 已加载", failures);
    var directDomainRules = ClashInspector.PinnedDomains
        .Select((d, i) => new ClashRuleEntry("DomainSuffix", d, i == 0 ? "DIRECT" : "MySelectGroup"))
        .Concat(ClashInspector.PinnedPorts.Select(p => new ClashRuleEntry("AND", $"((NETWORK,UDP),(DST-PORT,{p}))", "MySelectGroup")))
        .ToArray();
    Assert(!ClashInspector.ArePinnedRulesLoaded(directDomainRules, WebRtcPolicies.Proxy),
        "Claude 域名指向 DIRECT 时必须判定规则未正确加载", failures);

    // CleanupLegacyMergeRules: rules + --- + orphaned prepend-rules + duplicate top keys
    var mergePath = Path.Combine(clashDir, "profiles", "Merge.yaml");
    File.WriteAllText(
        mergePath,
        """
        ---
        mixed-port: 7897
        prepend-rules:
          - DOMAIN-SUFFIX,claude.ai,GLOBAL
          - DST-PORT,3478,GLOBAL
        dns:
          enable: true
        dns:
          enable: false
        """,
        new UTF8Encoding(false));
    var mergeFix = ClashInspector.CleanupLegacyMergeRules(clashDir);
    Assert(mergeFix.Success && mergeFix.Changed && !string.IsNullOrEmpty(mergeFix.BackupPath) && File.Exists(mergeFix.BackupPath),
        "清理遗留 Merge.yaml 应成功并生成备份：" + mergeFix.Message, failures);
    var cleanedMerge = File.ReadAllText(mergePath, Encoding.UTF8);
    Assert(cleanedMerge.Contains("mixed-port: 7897", StringComparison.Ordinal) &&
           !cleanedMerge.Contains("prepend-rules:", StringComparison.Ordinal) &&
           !cleanedMerge.Contains("claude.ai", StringComparison.Ordinal) &&
           !cleanedMerge.Contains("---", StringComparison.Ordinal) &&
           cleanedMerge.Contains("enable: true", StringComparison.Ordinal) &&
           !cleanedMerge.Contains("enable: false", StringComparison.Ordinal),
        "Merge.yaml 清理应移除旧规则、文档分隔符、空 prepend-rules 与重复顶层键", failures);
}
finally
{
    if (Directory.Exists(clashDir)) Directory.Delete(clashDir, true);
}

// =========================================================================
// 14. AccountSlotManager Residual Guards & Zip-Slip Protection Tests
// =========================================================================
var guardRoot = Path.Combine(Path.GetTempPath(), "cdg-guard-test-" + Guid.NewGuid().ToString("N"));
try
{
    var gBase = Path.Combine(guardRoot, "guardian");
    var gData = Path.Combine(guardRoot, "ClaudeData");
    Directory.CreateDirectory(gData);
    File.WriteAllText(Path.Combine(gData, "state.txt"), "acct-a");
    var gMgr = new AccountSlotManager(gBase, gData, () => true, () => true, () => true);

    // Initial switch A -> B -> A so A is current and archived
    Assert(gMgr.SwitchToSlot("B", true, null, false).Success, "初始切到 B 应成功", failures);
    Assert(gMgr.SwitchToSlot("A", true, null, false).Success, "切回 A 应成功", failures);

    // 14a. Residual accounts/A.new blocks switch
    var residualNew = Path.Combine(gBase, "accounts", "A.new");
    Directory.CreateDirectory(residualNew);
    var resBlocked = gMgr.SwitchToSlot("B", true, null, false);
    Assert(!resBlocked.Success && resBlocked.Message.Contains("待恢复快照", StringComparison.Ordinal),
        "存在 accounts/A.new 残留快照时必须拒绝覆盖", failures);
    Directory.Delete(residualNew, true);

    // 14b. Unowned staging/Claude.old blocks switch AND leaves no orphan Claude.new
    var stagingDir = Path.Combine(gBase, "staging");
    var oldDir = Path.Combine(stagingDir, "Claude.old");
    var stageNewDir = Path.Combine(stagingDir, "Claude.new");
    Directory.CreateDirectory(oldDir);
    File.WriteAllText(Path.Combine(oldDir, "unknown.txt"), "mystery");
    var unownedBlocked = gMgr.SwitchToSlot("B", true, null, false);
    Assert(!unownedBlocked.Success && unownedBlocked.Message.Contains("拒绝覆盖", StringComparison.Ordinal),
        "存在无归属标记的 Claude.old 时必须拒绝覆盖", failures);
    Assert(!Directory.Exists(stageNewDir), "因 Claude.old 中止切换时不应遗留 Claude.new 暂存目录", failures);

    // 14c. Valid owned cleanup.json allows automatic cleanup and switch success
    File.WriteAllText(
        Path.Combine(stagingDir, "cleanup.json"),
        JsonSerializer.Serialize(new { version = 1, path = oldDir, target = "A" }),
        new UTF8Encoding(false));
    var ownedCleared = gMgr.SwitchToSlot("B", true, null, false);
    Assert(ownedCleared.Success && !Directory.Exists(oldDir),
        "带有合法归属 cleanup.json 的 Claude.old 应被安全清理并完成切换：" + ownedCleared.Message, failures);

    // 14d. Zip-Slip attack blocked by EncryptedSnapshotService.ExtractSnapshotArchive
    var slipZip = Path.Combine(guardRoot, "slip.zip");
    var slipOut = Path.Combine(guardRoot, "extract");
    var escapedFile = Path.Combine(guardRoot, "evil-escape.txt");
    using (var z = ZipFile.Open(slipZip, ZipArchiveMode.Create))
    {
        var e = z.CreateEntry("../evil-escape.txt");
        using var w = new StreamWriter(e.Open(), Encoding.UTF8);
        w.Write("pwned");
    }

    AssertThrows<InvalidDataException>(
        () => EncryptedSnapshotService.ExtractSnapshotArchive(slipZip, slipOut),
        "Zip-Slip 路径穿越条目必须被 ExtractSnapshotArchive 拒绝",
        failures);
    Assert(!File.Exists(escapedFile), "Zip-Slip 拦截后不得在目标目录外写入文件", failures);
}
finally
{
    if (Directory.Exists(guardRoot)) Directory.Delete(guardRoot, true);
}

// =========================================================================
// 15. DNS Failure Anti-Swallow, System Proxy vs TUN Divergence, Evidence & Launch Gate
// =========================================================================
extProbe.ResetHealthy();
extProbe.ResolvedClaudeIps = Array.Empty<string>();
extProbe.DnsProbeDetailOverride = "claude.ai DNS 解析失败：No such host is known";
var dnsFailReport = await extEngine.RunAsync(new GuardianConfig(), full: true, CancellationToken.None);
Assert(
    dnsFailReport.Checks.Any(c => c.Id == GuardianCheckIds.Dns && c.Status == CheckStatus.Fail && c.Blocking),
    "claude.ai DNS 解析失败时必须判 Fail 阻断，不得静默吞成 Ok",
    failures);
extProbe.ResetHealthy();

// System proxy vs TUN divergence
extProbe.SystemProxyConfigured = true;
extProbe.SystemProxyUri = "http://127.0.0.1:7897";
extProbe.TunDirectExitIp = "203.0.113.10";
extProbe.TunDirectExitCountry = "US";
var dualMatchReport = await extEngine.RunAsync(new GuardianConfig(), full: true, CancellationToken.None);
var dualMatchCheck = dualMatchReport.Checks.First(c => c.Id == GuardianCheckIds.EgressIp);
Assert(dualMatchCheck.Status == CheckStatus.Ok &&
       dualMatchCheck.Evidence.TryGetValue("system_proxy", out var spVal) && spVal == "true" &&
       dualMatchCheck.Evidence.TryGetValue("tun_ip", out var tipVal) && tipVal == "203.0.113.10",
    "系统代理与 TUN 出口一致时应通过并保留双路径 Evidence", failures);

extProbe.TunDirectExitIp = "114.114.114.114";
extProbe.TunDirectExitCountry = "CN";
var dualCountryDiverge = await extEngine.RunAsync(new GuardianConfig(), full: true, CancellationToken.None);
var divergeCheck = dualCountryDiverge.Checks.First(c => c.Id == GuardianCheckIds.EgressIp);
Assert(divergeCheck.Status == CheckStatus.Fail && divergeCheck.Blocking &&
       divergeCheck.Detail.Contains("114.114.114.114", StringComparison.Ordinal) &&
       divergeCheck.Evidence.GetValueOrDefault("tun_country") == "CN",
    "系统代理与 TUN 国家不一致或 TUN 落回 CN 时必须 Fail 阻断并保留双证据", failures);

extProbe.TunDirectExitIp = "198.51.100.88";
extProbe.TunDirectExitCountry = "US";
var dualIpDiverge = await extEngine.RunAsync(new GuardianConfig(), full: true, CancellationToken.None);
Assert(dualIpDiverge.Checks.Any(c => c.Id == GuardianCheckIds.EgressIp && c.Status == CheckStatus.Unknown && c.Blocking),
    "系统代理与 TUN 同国不同出口 IP 时应判 Unknown 阻断", failures);

extProbe.TunDirectExitIp = string.Empty;
extProbe.TunDirectExitCountry = string.Empty;
extProbe.TunDirectProbeDetail = "连接超时";
var dualTunMissing = await extEngine.RunAsync(new GuardianConfig(), full: true, CancellationToken.None);
Assert(dualTunMissing.Checks.Any(c => c.Id == GuardianCheckIds.EgressIp && c.Status == CheckStatus.Unknown && c.Blocking),
    "系统代理开启但 TUN 路径无出口时应判 Unknown 阻断", failures);
extProbe.ResetHealthy();

// Structured Evidence populated across all 23 checks
var evidenceReport = await extEngine.RunAsync(new GuardianConfig(), full: true, CancellationToken.None);
Assert(evidenceReport.Checks.Count == 23 && evidenceReport.Checks.All(c => c.Evidence.Count > 0),
    "全部 23 项检查均必须填充非空结构化 Evidence 字典", failures);

// Safe Launch Gate
Assert(!ProtectionPolicyEvaluator.EvaluateLaunchGate(evidenceReport, currentlyBlocked: true, ignoreWebRtc: false).Allowed,
    "阻断锁定状态下安全启动门禁必须拒绝启动", failures);
Assert(!ProtectionPolicyEvaluator.EvaluateLaunchGate(null, currentlyBlocked: false, ignoreWebRtc: false).Allowed,
    "未完成检查时安全启动门禁必须拒绝启动", failures);
Assert(ProtectionPolicyEvaluator.EvaluateLaunchGate(evidenceReport, currentlyBlocked: false, ignoreWebRtc: false).Allowed,
    "环境健康且未阻断时安全启动门禁应允许启动", failures);
extProbe.WfpPolicyState = "stale";
var staleWfpReport = await extEngine.RunAsync(new GuardianConfig(WfpStrictEnabled: true), full: true, CancellationToken.None);
Assert(!ProtectionPolicyEvaluator.EvaluateLaunchGate(staleWfpReport, currentlyBlocked: false, ignoreWebRtc: false).Allowed,
    "WFP 严格模式过期时安全启动门禁必须拒绝启动", failures);
extProbe.ResetHealthy();

// =========================================================================
// 16. Privileged Helper Mock Executor Tests (Zero Real Firewall/WFP/TZ Edits)
// =========================================================================
var fakeExec = new FakeHelperExecutor();
var dispatcher = new HelperCommandDispatcher(fakeExec);

static JsonElement ParseResp(object response)
{
    var json = JsonSerializer.Serialize(response);
    return JsonDocument.Parse(json).RootElement.Clone();
}

var badTokenResp = ParseResp(await dispatcher.HandleLineAsync(
    JsonSerializer.Serialize(new { token = "wrong-token", command = "status" })));
Assert(!badTokenResp.GetProperty("ok").GetBoolean(), "错误 Token 必须被 Helper 拒绝", failures);

var badCmdResp = ParseResp(await dispatcher.HandleLineAsync(
    JsonSerializer.Serialize(new { token = fakeExec.Token, command = "exec-shell" })));
Assert(!badCmdResp.GetProperty("ok").GetBoolean(), "未知命令必须被 Helper 拒绝", failures);

var statusResp = ParseResp(await dispatcher.HandleLineAsync(
    JsonSerializer.Serialize(new { token = fakeExec.Token, command = "status", allowLoopback = true })));
Assert(statusResp.GetProperty("ok").GetBoolean() &&
       statusResp.GetProperty("group").GetString() == "ClaudeDesktopGuardian.S-1-5-21-fake" &&
       statusResp.GetProperty("firewallApiOk").GetBoolean() &&
       statusResp.GetProperty("wfpState").GetString() == "active",
    "Helper status 应返回真实组名、防火墙 API 与 WFP 状态", failures);

// apply-block filters disallowed paths and stays idempotent across repeated invocations
var blockPayload = JsonSerializer.Serialize(new
{
    token = fakeExec.Token,
    command = "apply-block",
    paths = new[] { @"C:\Users\Test\AppData\Local\Programs\Claude\Claude.exe", @"C:\Windows\System32\cmd.exe" }
});
var b1 = ParseResp(await dispatcher.HandleLineAsync(blockPayload));
var b2 = ParseResp(await dispatcher.HandleLineAsync(blockPayload));
Assert(b1.GetProperty("ok").GetBoolean() && b2.GetProperty("ok").GetBoolean(), "重复 apply-block 应成功", failures);
Assert(fakeExec.ActiveFirewallRules.All(r => !r.ProgramPath.EndsWith("cmd.exe", StringComparison.OrdinalIgnoreCase)),
    "apply-block 不得为非 Claude 路径添加防火墙规则", failures);
Assert(fakeExec.ActiveFirewallRules.Count == 2,
    $"重复触发 apply-block 不得堆积重复规则（期望 2 条，实际 {fakeExec.ActiveFirewallRules.Count} 条）", failures);

// clear-block clears only current user's group
fakeExec.ActiveFirewallRules.Add(("OtherApp.Rule", "OtherGroup", @"C:\Other\app.exe"));
var clearResp = ParseResp(await dispatcher.HandleLineAsync(
    JsonSerializer.Serialize(new { token = fakeExec.Token, command = "clear-block" })));
Assert(clearResp.GetProperty("ok").GetBoolean() &&
       fakeExec.ActiveFirewallRules.Count == 1 &&
       fakeExec.ActiveFirewallRules[0].Group == "OtherGroup",
    "clear-block 必须仅移除本程序用户组规则而不影响其他规则", failures);

// terminate-tree kills ONLY current-user Claude processes
var termResp = ParseResp(await dispatcher.HandleLineAsync(
    JsonSerializer.Serialize(new { token = fakeExec.Token, command = "terminate-tree", processIds = new[] { 1001, 2002, 9999 } })));
Assert(termResp.GetProperty("ok").GetBoolean() &&
       termResp.GetProperty("terminated").GetInt32() == 1 &&
       termResp.GetProperty("rejected").GetInt32() == 2 &&
       fakeExec.TerminatedPids.SequenceEqual(new[] { 1001 }),
    "terminate-tree 必须只终止当前用户的 Claude 进程并拒绝无关/跨用户 PID", failures);

// apply-timezone validation
var badTzResp = ParseResp(await dispatcher.HandleLineAsync(
    JsonSerializer.Serialize(new { token = fakeExec.Token, command = "apply-timezone", timezoneId = "NotARealZone" })));
Assert(!badTzResp.GetProperty("ok").GetBoolean(), "未知 Windows 时区 ID 必须被 Helper 拒绝", failures);
var okTzResp = ParseResp(await dispatcher.HandleLineAsync(
    JsonSerializer.Serialize(new { token = fakeExec.Token, command = "apply-timezone", timezoneId = "Pacific Standard Time" })));
Assert(okTzResp.GetProperty("ok").GetBoolean() && fakeExec.CurrentTimezone == "Pacific Standard Time",
    "合法 Windows 时区应通过 Helper 生效", failures);

// wfp-enable reports remaining count + wfp-disable removes sublayer
fakeExec.SimulatedRemainingAfterWfpKill = 1;
var wfpEnResp = ParseResp(await dispatcher.HandleLineAsync(
    JsonSerializer.Serialize(new { token = fakeExec.Token, command = "wfp-enable", adapterGuid = "{11111111-2222-3333-4444-555555555555}", allowLoopback = true })));
Assert(wfpEnResp.GetProperty("ok").GetBoolean() && wfpEnResp.GetProperty("remainingCount").GetInt32() == 1,
    "wfp-enable 应如实返回旧进程退出复核结果", failures);
var wfpDisResp = ParseResp(await dispatcher.HandleLineAsync(
    JsonSerializer.Serialize(new { token = fakeExec.Token, command = "wfp-disable" })));
Assert(wfpDisResp.GetProperty("ok").GetBoolean() && fakeExec.WfpRemovedCount == 1, "wfp-disable 应移除 WFP 子层", failures);

// disable-ipv6-adapters rejects control chars and disables valid adapters
var badIpv6Resp = ParseResp(await dispatcher.HandleLineAsync(
    JsonSerializer.Serialize(new { token = fakeExec.Token, command = "disable-ipv6-adapters", adapterNames = new[] { "Bad\nName" } })));
Assert(!badIpv6Resp.GetProperty("ok").GetBoolean(), "含控制字符的网卡名称必须被拒绝", failures);
var okIpv6Resp = ParseResp(await dispatcher.HandleLineAsync(
    JsonSerializer.Serialize(new { token = fakeExec.Token, command = "disable-ipv6-adapters", adapterNames = new[] { "Ethernet" } })));
Assert(okIpv6Resp.GetProperty("ok").GetBoolean() && fakeExec.DisabledIpv6Adapters.Contains("Ethernet"),
    "合法非 VPN 网卡应调用禁用 IPv6 绑定", failures);

// --cleanup-all removes WFP, clears all Guardian rules, restores original timezone & clears blocked state
var cleanupStatePath = Path.Combine(Path.GetTempPath(), "cdg-cleanup-state-" + Guid.NewGuid().ToString("N") + ".json");
try
{
    var csStore = new GuardianStateStore(cleanupStatePath);
    csStore.Save(new GuardianState(
        Blocked: true,
        TripReason: "测试阻断",
        BlockedAt: DateTimeOffset.UtcNow,
        LastCheckedAt: DateTimeOffset.UtcNow,
        TimezoneOverrideActive: true,
        OriginalWindowsTimezone: "China Standard Time",
        AppliedWindowsTimezone: "Pacific Standard Time"));
    var cleanupCode = await dispatcher.RunCleanupAllAsync(cleanupStatePath);
    var cleanedState = csStore.Load();
    Assert(cleanupCode == 0 &&
           fakeExec.WfpRemovedCount >= 2 &&
           fakeExec.ClearedAllPrefix == "ClaudeDesktopGuardian." &&
           fakeExec.CurrentTimezone == "China Standard Time" &&
           !cleanedState.Blocked &&
           !cleanedState.TimezoneOverrideActive,
        "--cleanup-all 应移除 WFP、清理全部 Guardian 防火墙规则并恢复原始时区与状态", failures);
}
finally
{
    if (File.Exists(cleanupStatePath)) File.Delete(cleanupStatePath);
}

// =========================================================================
// 17. WPF Resource Dictionary, Status Colors & Button Gate Tests (STA)
// =========================================================================
string? wpfResourceError = null;
var staThread = new Thread(() =>
{
    try
    {
        var appXamlPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..",
            "src", "ClaudeDesktopGuardian.App", "App.xaml"));
        if (!File.Exists(appXamlPath))
        {
            wpfResourceError = $"未找到 App.xaml：{appXamlPath}";
            return;
        }

        var xdoc = XDocument.Load(appXamlPath);
        XNamespace wpfNs = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xNs = "http://schemas.microsoft.com/winfx/2006/xaml";
        var dictEl = xdoc.Descendants(wpfNs + "ResourceDictionary").FirstOrDefault();
        if (dictEl is null)
        {
            var appResourcesEl = xdoc.Descendants(wpfNs + "Application.Resources").FirstOrDefault();
            if (appResourcesEl is null)
            {
                wpfResourceError = "App.xaml 缺少 Application.Resources";
                return;
            }

            dictEl = new XElement(
                wpfNs + "ResourceDictionary",
                new XAttribute(XNamespace.Xmlns + "x", xNs.NamespaceName),
                appResourcesEl.Elements());
        }

        var dict = (ResourceDictionary)XamlReader.Parse(dictEl.ToString());
        foreach (var key in UiPresentationState.RequiredStatusBrushKeys)
        {
            if (!dict.Contains(key) || dict[key] is not SolidColorBrush)
            {
                wpfResourceError = $"App.xaml 缺少状态画刷资源键或类型不是 SolidColorBrush：{key}";
                return;
            }
        }
    }
    catch (Exception ex)
    {
        wpfResourceError = $"加载 App.xaml 资源字典失败：{ex.Message}";
    }
});
staThread.SetApartmentState(ApartmentState.STA);
staThread.Start();
staThread.Join();
Assert(wpfResourceError is null, wpfResourceError ?? string.Empty, failures);

var uiHealthy = UiPresentationState.Evaluate(evidenceReport, blocked: false, ignoreWebRtc: false);
Assert(uiHealthy.Badge.Label == "正常" &&
       uiHealthy.Badge.ForegroundResourceKey == "StatusOkBrush" &&
       uiHealthy.CanLaunchClaude &&
       uiHealthy.TripReasonDisplay == "暂无",
    "WPF 展示模型在健康状态下应显示绿色正常并开放安全启动", failures);

var uiBlockedHealthy = UiPresentationState.Evaluate(evidenceReport, blocked: true, ignoreWebRtc: false);
Assert(uiBlockedHealthy.Badge.Label == "已阻断" &&
       uiBlockedHealthy.Badge.ForegroundResourceKey == "StatusWarnBrush" &&
       !uiBlockedHealthy.CanLaunchClaude &&
       uiBlockedHealthy.CanRecoverNow,
    "WPF 展示模型在已阻断但当前检查健康时应禁止直接启动并允许解除阻断", failures);

var uiBlockedFail = UiPresentationState.Evaluate(smFailReport, blocked: true, ignoreWebRtc: false);
Assert(!uiBlockedFail.CanLaunchClaude && !uiBlockedFail.CanRecoverNow && !string.IsNullOrWhiteSpace(uiBlockedFail.TripReasonDisplay),
    "WPF 展示模型在已阻断且仍有失败时必须禁止启动与解除并展示原因", failures);

var uiWebRtcUnknownRaw = UiPresentationState.Evaluate(incompleteBrowserReport, blocked: false, ignoreWebRtc: false);
var uiWebRtcUnknownIgnored = UiPresentationState.Evaluate(incompleteBrowserReport, blocked: false, ignoreWebRtc: true);
Assert(uiWebRtcUnknownRaw.Badge.Label == "未验证" && uiWebRtcUnknownIgnored.Badge.Label == "正常",
    "忽略 WebRTC 未验证开关应正确影响 WPF 主状态徽章", failures);

var uiWebRtcLeakIgnored = UiPresentationState.Evaluate(leakingBrowserReport, blocked: false, ignoreWebRtc: true);
Assert(uiWebRtcLeakIgnored.Badge.Label == "异常" &&
       uiWebRtcLeakIgnored.Badge.ForegroundResourceKey == "StatusErrorBrush" &&
       !uiWebRtcLeakIgnored.CanLaunchClaude,
    "开启忽略 WebRTC 未验证时，确认公网泄露仍必须显示红色异常并禁止启动", failures);

Assert(UiPresentationState.FormatExitPathSummary(dualCountryDiverge.Network).Contains("114.114.114.114", StringComparison.Ordinal),
    "系统代理启用时出口摘要必须同时包含代理与 TUN 双路径地址", failures);

// =========================================================================
// 18. Multi-Account Claude Code CLI Graceful-Exit Red Line
// =========================================================================
var cliGuardRoot = Path.Combine(Path.GetTempPath(), "cdg-cliguard-" + Guid.NewGuid().ToString("N"));
try
{
    var cgBase = Path.Combine(cliGuardRoot, "guardian");
    var cgData = Path.Combine(cliGuardRoot, "ClaudeData");
    Directory.CreateDirectory(cgData);
    File.WriteAllText(Path.Combine(cgData, "token.txt"), "account-a-live");

    var blockingCliMgr = new AccountSlotManager(
        cgBase, cgData,
        stopClaudeOverride: () => true,
        startClaudeOverride: () => true,
        stopCliOverride: () => false);
    var aborted = blockingCliMgr.SwitchToSlot("B", environmentHealthy: true, null, launchAfterSwitch: false);
    Assert(!aborted.Success && aborted.Message.Contains("Claude Code CLI", StringComparison.Ordinal),
        "Claude Code CLI 未退出时必须中止账号切换", failures);
    Assert(File.ReadAllText(Path.Combine(cgData, "token.txt")) == "account-a-live" &&
           string.IsNullOrEmpty(blockingCliMgr.GetCurrentSlot()),
        "因 CLI 未退出中止切换后，桌面数据与槽位指针必须原封不动", failures);

    var okCliMgr = new AccountSlotManager(
        cgBase, cgData,
        stopClaudeOverride: () => true,
        startClaudeOverride: () => true,
        stopCliOverride: () => true);
    var switched = okCliMgr.SwitchToSlot("B", environmentHealthy: true, null, launchAfterSwitch: false);
    Assert(switched.Success && okCliMgr.GetCurrentSlot() == "B",
        "CLI 正常退出后切换账号应成功：" + switched.Message, failures);
}
finally
{
    if (Directory.Exists(cliGuardRoot)) Directory.Delete(cliGuardRoot, true);
}

// =========================================================================
// 19. GuardianCliRunner Offline Contract & diagnose-proxy --config
// =========================================================================
var cliRoot = Path.Combine(Path.GetTempPath(), "cdg-cli-" + Guid.NewGuid().ToString("N"));
try
{
    Directory.CreateDirectory(cliRoot);
    var cliCfgPath = Path.Combine(cliRoot, "config.json");
    var cliStatePath = Path.Combine(cliRoot, "state.json");
    var cliLogPath = Path.Combine(cliRoot, "logs", "guardian.log");
    var cliDataPath = Path.Combine(cliRoot, "ClaudeData");

    GuardianCliContext MakeCliCtx(StringWriter stdout, StringWriter stderr, TextReader? stdin = null, Func<string, string?>? env = null) =>
        new()
        {
            ConfigStore = new GuardianConfigStore(cliCfgPath),
            StateStore = new GuardianStateStore(cliStatePath),
            AccountManager = new AccountSlotManager(cliRoot, cliDataPath, () => true, () => true, () => true),
            Logger = new GuardianLogger(cliLogPath),
            Probe = extProbe,
            ProcessInspector = inspector,
            Out = stdout,
            Error = stderr,
            In = stdin ?? TextReader.Null,
            GetEnvironmentVariable = env ?? (_ => null)
        };

    // 19a. diagnose-proxy --config MUST NOT write client log or create accounts dir
    var badDiagCfg = Path.Combine(cliRoot, "proxy-bad.json");
    File.WriteAllText(badDiagCfg, """{"proxy_url":"ftp://127.0.0.1:21"}""", new UTF8Encoding(false));
    var diagOut = new StringWriter();
    var diagErr = new StringWriter();
    var diagCode = await GuardianCliRunner.RunAsync(
        new[] { "diagnose-proxy", "--config", badDiagCfg },
        MakeCliCtx(diagOut, diagErr));
    Assert(diagCode == 2 && diagOut.ToString().Contains("\"configuration_error\"", StringComparison.Ordinal),
        "diagnose-proxy --config 非法协议应返回退出码 2 与 configuration_error JSON", failures);
    Assert(!File.Exists(cliLogPath) && !Directory.Exists(Path.Combine(cliRoot, "accounts")),
        "独立代理诊断绝不得写入客户端日志或创建账号目录", failures);

    // 19b. set-check-config & get-check-config (key never echoed)
    var setOut = new StringWriter();
    var setErr = new StringWriter();
    var setCode = await GuardianCliRunner.RunAsync(
        new[]
        {
            "set-check-config",
            """{"disabled":["dns"],"allowOptionalFailures":true,"webrtcPolicy":"reject","ipReputation":{"url":"https://rep.cli.test/{ip}","key":"TOP-SECRET-CLI-KEY","threshold":30,"cacheDays":14}}"""
        },
        MakeCliCtx(setOut, setErr));
    Assert(setCode == 0, "CLI set-check-config 应成功：" + setErr, failures);

    var getOut = new StringWriter();
    var getCode = await GuardianCliRunner.RunAsync(new[] { "get-check-config" }, MakeCliCtx(getOut, new StringWriter()));
    var getJson = getOut.ToString();
    Assert(getCode == 0 &&
           getJson.Contains("\"keyConfigured\":true", StringComparison.Ordinal) &&
           getJson.Contains("\"webrtcPolicy\":\"reject\"", StringComparison.Ordinal) &&
           !getJson.Contains("TOP-SECRET-CLI-KEY", StringComparison.Ordinal),
        "CLI get-check-config 必须回报 keyConfigured 且绝不回显明文密钥", failures);

    // 19c. set-client / get-client / set-flclash-controller / checkdetail
    Assert(await GuardianCliRunner.RunAsync(new[] { "set-client", "flclash" }, MakeCliCtx(new StringWriter(), new StringWriter())) == 0,
        "CLI set-client flclash 应成功", failures);
    var clientOut = new StringWriter();
    _ = await GuardianCliRunner.RunAsync(new[] { "get-client" }, MakeCliCtx(clientOut, new StringWriter()));
    Assert(clientOut.ToString().Trim() == "flclash", "CLI get-client 应返回 flclash", failures);

    extProbe.ResetHealthy();
    var detailOut = new StringWriter();
    var detailCode = await GuardianCliRunner.RunAsync(new[] { "checkdetail" }, MakeCliCtx(detailOut, new StringWriter()));
    var detailLines = detailOut.ToString().Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
    Assert(detailCode == 0 && detailLines.Length == 23,
        $"CLI checkdetail 应返回 0 且输出 23 行（实际 code={detailCode}, lines={detailLines.Length}）", failures);

    // 19d. snapshot-export & snapshot-import via stdin password
    Directory.CreateDirectory(cliDataPath);
    File.WriteAllText(Path.Combine(cliDataPath, "cli-a.txt"), "from-cli-slot-a");
    Assert(await GuardianCliRunner.RunAsync(new[] { "switch", "B", "--no-launch" }, MakeCliCtx(new StringWriter(), new StringWriter())) == 0,
        "CLI switch B 应成功将现有数据归档至 A", failures);
    var cliSnapFile = Path.Combine(cliRoot, "cli-slot-a.csnap");
    var expOut = new StringWriter();
    var expErr = new StringWriter();
    var expCode = await GuardianCliRunner.RunAsync(
        new[] { "snapshot-export", "A", cliSnapFile },
        MakeCliCtx(expOut, expErr, stdin: new StringReader("CliStrongPass!2026\n")));
    Assert(expCode == 0 && File.Exists(cliSnapFile), "CLI snapshot-export (stdin 密码) 应成功：" + expErr, failures);

    var impRoot = Path.Combine(cliRoot, "import-target");
    var impCtx = new GuardianCliContext
    {
        ConfigStore = new GuardianConfigStore(Path.Combine(impRoot, "config.json")),
        StateStore = new GuardianStateStore(Path.Combine(impRoot, "state.json")),
        AccountManager = new AccountSlotManager(impRoot, Path.Combine(impRoot, "ClaudeData"), () => true, () => true, () => true),
        Logger = new GuardianLogger(Path.Combine(impRoot, "logs", "guardian.log")),
        Out = new StringWriter(),
        Error = new StringWriter(),
        In = new StringReader("CliStrongPass!2026\n")
    };
    var impCode = await GuardianCliRunner.RunAsync(new[] { "snapshot-import", cliSnapFile, "A" }, impCtx);
    Assert(impCode == 0 && File.Exists(Path.Combine(impRoot, "accounts", "A", "cli-a.txt")),
        "CLI snapshot-import (stdin 密码) 应完整还原快照到空槽位 A", failures);
}
finally
{
    if (Directory.Exists(cliRoot)) Directory.Delete(cliRoot, true);
}

// =========================================================================
// 20. Hot-Path Optimization Tests (MSIX Family Parser + Two-Phase Process Filter)
// =========================================================================
Assert(
    ClaudeInstallDiscovery.TryExtractPackageFamilyName("Claude_6.28899.6.0_x64__pzs8sxrjxfjjc") == "Claude_pzs8sxrjxfjjc",
    "应精确解析真实 MSIX PackageFullName 为 PackageFamilyName",
    failures);
Assert(
    ClaudeInstallDiscovery.TryExtractPackageFamilyName("invalid-package") is null,
    "非法 MSIX 包名应返回 null",
    failures);

var rawEntries = new List<RawProcessEntry>(210);
for (var pid = 100; pid < 300; pid++)
{
    rawEntries.Add(new RawProcessEntry(pid, 4, pid % 2 == 0 ? "svchost.exe" : "chrome.exe"));
}
rawEntries.Add(new RawProcessEntry(5000, 100, "Claude.exe"));
rawEntries.Add(new RawProcessEntry(5001, 5000, "Claude.exe"));
rawEntries.Add(new RawProcessEntry(5002, 5001, "node.exe"));
rawEntries.Add(new RawProcessEntry(6000, 100, "Claude.exe")); // another user's SID

var inspectedPids = new List<int>();
var filteredTree = WindowsProcessInspector.FilterClaudeTree(
    rawEntries,
    pid =>
    {
        inspectedPids.Add(pid);
        return pid switch
        {
            5000 => (@"C:\Users\Me\AppData\Local\Programs\Claude\Claude.exe", "S-1-5-21-me"),
            5001 => (@"C:\Users\Me\AppData\Local\Programs\Claude\Claude.exe", "S-1-5-21-me"),
            5002 => (@"C:\Users\Me\AppData\Local\Programs\Claude\resources\node.exe", "S-1-5-21-me"),
            6000 => (@"C:\Users\Other\AppData\Local\Programs\Claude\Claude.exe", "S-1-5-21-other"),
            _ => (@"C:\Windows\System32\svchost.exe", "S-1-5-18")
        };
    },
    "S-1-5-21-me");
Assert(filteredTree.Select(p => p.ProcessId).OrderBy(id => id).SequenceEqual(new[] { 5000, 5001, 5002 }),
    "两阶段过滤应准确返回当前用户的 Claude 根与子进程树并排除跨用户进程", failures);
Assert(inspectedPids.Count == 4 && inspectedPids.All(pid => pid >= 5000),
    $"两阶段过滤不得对 200 个无关系统进程触发句柄查询（实际查询 {inspectedPids.Count} 次）", failures);

// =========================================================================
// 21. PipeTokenStore Concurrency, IpReputationService Expiry/LRU & {ip} Diag Host
// =========================================================================
var raceTokenPath = Path.Combine(Path.GetTempPath(), "cdg-race-token-" + Guid.NewGuid().ToString("N"));
try
{
    var tokenTasks = Enumerable.Range(0, 8)
        .Select(_ => Task.Run(() => new PipeTokenStore(raceTokenPath).GetOrCreate()))
        .ToArray();
    var tokens = await Task.WhenAll(tokenTasks);
    Assert(tokens.All(t => t.Length >= 32 && t == tokens[0]),
        "8 路并发冷启动 PipeTokenStore 必须返回完全一致的认证令牌", failures);
    var reReadStore = new PipeTokenStore(raceTokenPath);
    reReadStore.InvalidateCache();
    Assert(reReadStore.GetOrCreate() == tokens[0], "清除内存缓存后应从磁盘稳定读回同一令牌", failures);
}
finally
{
    if (File.Exists(raceTokenPath)) File.Delete(raceTokenPath);
}

var repOptCachePath = Path.Combine(Path.GetTempPath(), "cdg-rep-opt-" + Guid.NewGuid().ToString("N") + ".json");
var repLruCachePath = Path.Combine(Path.GetTempPath(), "cdg-rep-lru-" + Guid.NewGuid().ToString("N") + ".json");
var diagTplZipPath = Path.Combine(Path.GetTempPath(), "cdg-diag-tpl-" + Guid.NewGuid().ToString("N") + ".zip");
try
{
    // 21a. Expired cache + failed refresh MUST report error (never silently serve stale cache)
    var failNetwork = false;
    var expiryHandler = new MockHttpHandler(_ => failNetwork
        ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
        : new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""{"fraud_score": 12, "is_proxy": false}""", Encoding.UTF8, "application/json")
        });
    using var expiryHttp = new HttpClient(expiryHandler);
    var expirySvc = new IpReputationService(expiryHttp, repOptCachePath);
    var tBase = new DateTimeOffset(2026, 11, 20, 0, 0, 0, TimeSpan.Zero);
    var expiryCfg = new IpReputationConfig("https://rep.expiry.test/ip", "k", 25, CacheDays: 7);

    var (freshRec, freshErr) = await expirySvc.LookupAsync("203.0.113.50", expiryCfg, tBase, CancellationToken.None);
    Assert(freshRec?.Score == 12 && string.IsNullOrEmpty(freshErr), "首次信誉查询应成功并写入缓存", failures);

    failNetwork = true;
    var (expiredRec, expiredErr) = await expirySvc.LookupAsync("203.0.113.50", expiryCfg, tBase.AddDays(10), CancellationToken.None);
    Assert(expiredRec is null && expiredErr.Contains("过期", StringComparison.Ordinal),
        "过期缓存遇接口失败必须显式回报过期刷新失败，不得静默伪装新鲜结果", failures);

    // 21b. LRU eviction keeps newest IP cached when cache exceeds byte budget
    var lruHandler = new MockHttpHandler(req => new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new StringContent("""{"fraud_score": 5, "is_proxy": false}""", Encoding.UTF8, "application/json")
    });
    using var lruHttp = new HttpClient(lruHandler);
    var lruSvc = new IpReputationService(lruHttp, repLruCachePath, maxCacheBytes: 380);
    var lruCfg = new IpReputationConfig("https://rep.lru.test/ip", "k", 25, CacheDays: 7);
    _ = await lruSvc.LookupAsync("198.51.100.1", lruCfg, tBase, CancellationToken.None);
    _ = await lruSvc.LookupAsync("198.51.100.2", lruCfg, tBase.AddMinutes(1), CancellationToken.None);
    _ = await lruSvc.LookupAsync("198.51.100.3", lruCfg, tBase.AddMinutes(2), CancellationToken.None);
    var countBeforeRequery = lruHandler.RequestCount;
    var (newestCached, _) = await lruSvc.LookupAsync("198.51.100.3", lruCfg, tBase.AddMinutes(3), CancellationToken.None);
    Assert(newestCached?.Score == 5 && lruHandler.RequestCount == countBeforeRequery,
        "超过字节上限时 LRU 淘汰最旧条目后，最新 IP 仍应命中缓存", failures);

    // 21c. DiagnosticsExporter extracts url_host accurately from {ip} template URL
    DiagnosticsExporter.ExportZip(
        diagTplZipPath,
        new GuardianConfig(IpReputation: new IpReputationConfig("https://rep.template.test/v1/{ip}/score", "KEY-TPL-SECRET", 25, 7)),
        new GuardianState(false, string.Empty, null, DateTimeOffset.UtcNow),
        evidenceReport,
        new GuardianLogger(Path.Combine(Path.GetTempPath(), "cdg-tpl-nolog-" + Guid.NewGuid().ToString("N") + ".log")));
    using var tplZip = ZipFile.OpenRead(diagTplZipPath);
    using var tplSr = new StreamReader(tplZip.GetEntry("config-redacted.json")!.Open(), Encoding.UTF8);
    var tplJson = tplSr.ReadToEnd();
    Assert(tplJson.Contains("\"url_host\": \"rep.template.test\"", StringComparison.Ordinal) &&
           !tplJson.Contains("KEY-TPL-SECRET", StringComparison.Ordinal),
        "诊断包应从含 {ip} 占位符的模板 URL 准确提取 url_host 且不泄漏密钥", failures);
}
finally
{
    if (File.Exists(repOptCachePath)) File.Delete(repOptCachePath);
    if (File.Exists(repLruCachePath)) File.Delete(repLruCachePath);
    if (File.Exists(diagTplZipPath)) File.Delete(diagTplZipPath);
}

// =========================================================================
// 22. Helper Concurrent Read-vs-Write Isolation & Subprocess Timeout Protection
// =========================================================================
var slowExec = new FakeHelperExecutor { ClearDelayMs = 350 };
var concurrentDispatcher = new HelperCommandDispatcher(slowExec);
var slowMutateTask = concurrentDispatcher.HandleLineAsync(
    JsonSerializer.Serialize(new { token = slowExec.Token, command = "apply-block", paths = Array.Empty<string>() }));
await Task.Delay(40);
var swStatus = System.Diagnostics.Stopwatch.StartNew();
var fastStatusResp = ParseResp(await concurrentDispatcher.HandleLineAsync(
    JsonSerializer.Serialize(new { token = slowExec.Token, command = "status" })));
swStatus.Stop();
var slowMutateResp = ParseResp(await slowMutateTask);
Assert(fastStatusResp.GetProperty("ok").GetBoolean() && swStatus.ElapsedMilliseconds < 250,
    $"写命令执行期间只读 status 必须无阻塞快速返回（实际耗时 {swStatus.ElapsedMilliseconds} ms）", failures);
Assert(slowMutateResp.GetProperty("ok").GetBoolean(), "慢写命令 apply-block 应正常完成", failures);

var timedOutProperly = false;
try
{
    await WindowsHelperSystemExecutor.RunProcessWithTimeoutAsync("powershell.exe", 350, "-NoProfile", "-Command", "Start-Sleep -Seconds 5");
}
catch (TimeoutException)
{
    timedOutProperly = true;
}
Assert(timedOutProperly, "Helper 外部子进程超过超时阈值时必须强制终止并抛出 TimeoutException", failures);

// =========================================================================
// 23. UiPresentationState Selected Check Evidence Formatting
// =========================================================================
var emptyEvText = UiPresentationState.FormatCheckEvidence(null);
Assert(emptyEvText.Contains("任意一行", StringComparison.Ordinal), "未选中检查项时应显示引导提示", failures);
var formattedEv = UiPresentationState.FormatCheckEvidence(dualMatchCheck);
Assert(formattedEv.Contains("egress-ip", StringComparison.Ordinal) &&
       formattedEv.Contains("system_proxy = true", StringComparison.Ordinal) &&
       formattedEv.Contains("tun_ip = 203.0.113.10", StringComparison.Ordinal),
    "选中检查项 Evidence 格式化应完整输出检查 ID 与结构化键值", failures);

// =========================================================================
// 24. Clash Verge 2.x Named-Pipe HTTP (Chunked), TUN Mismatch Diag & STUN Dedup
// =========================================================================
Assert(
    ClashInspector.NormalizePipeName(@"\\.\pipe\verge-mihomo-production-abc123") == "verge-mihomo-production-abc123" &&
    ClashInspector.NormalizePipeName(@"..\evil") is null,
    "Clash 管道名解析应剥离 \\\\.\\pipe\\ 前缀并拒绝非法路径字符",
    failures);

var mismatchDiag = ClashInspector.FormatClashVergeTunDiagnostic(
    uiTunEnabled: true, liveTunEnabled: false, fileSource: null, fileTunEnabled: null);
Assert(mismatchDiag.Contains("已打开 TUN 开关", StringComparison.Ordinal) &&
       mismatchDiag.Contains("System/Mixed", StringComparison.Ordinal),
    "UI 已开 TUN 但运行内核 tun.enable=false 时应给出切堆栈与重启内核指引", failures);

var missingAdapterDiag = ClashInspector.FormatClashVergeTunDiagnostic(
    uiTunEnabled: true, liveTunEnabled: true, fileSource: null, fileTunEnabled: null);
Assert(missingAdapterDiag.Contains("未出现在线 TUN 网卡", StringComparison.Ordinal),
    "内核已开 TUN 但缺少网卡时应提示检查服务模式/Wintun", failures);

Assert(
    WindowsEnvironmentProbe.DeduplicateStunDetails(new[] { "IPv4 STUN 超时", "IPv4 STUN 超时", "IPv4 STUN 超时" }) == "IPv4 STUN 超时",
    "STUN 多 IP 同类超时明细应自动去重",
    failures);

var mockPipeName = "cdg-test-mihomo-" + Guid.NewGuid().ToString("N");
using (var pipeCts = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
{
    var rulesJson = JsonSerializer.Serialize(new
    {
        rules = ClashInspector.PinnedDomains
            .Select(d => new { type = "DomainSuffix", payload = d, proxy = "US-Node" })
            .Concat(ClashInspector.PinnedPorts.Select(p => new { type = "AND", payload = $"((NETWORK,UDP),(DST-PORT,{p}))", proxy = "US-Node" }))
            .ToArray()
    });
    var rulesBytes = Encoding.UTF8.GetBytes(rulesJson);
    var half = rulesBytes.Length / 2;
    var chunk1 = Encoding.UTF8.GetString(rulesBytes, 0, half);
    var chunk2 = Encoding.UTF8.GetString(rulesBytes, half, rulesBytes.Length - half);

    var serverTask = Task.Run(async () =>
    {
        for (var reqNo = 0; reqNo < 2; reqNo++)
        {
            await using var srv = new System.IO.Pipes.NamedPipeServerStream(
                mockPipeName,
                System.IO.Pipes.PipeDirection.InOut,
                2,
                System.IO.Pipes.PipeTransmissionMode.Byte,
                System.IO.Pipes.PipeOptions.Asynchronous);
            await srv.WaitForConnectionAsync(pipeCts.Token);
            using var reader = new StreamReader(srv, Encoding.ASCII, leaveOpen: true);
            var reqLine = await reader.ReadLineAsync(pipeCts.Token) ?? string.Empty;
            while (!string.IsNullOrEmpty(await reader.ReadLineAsync(pipeCts.Token))) { }

            string httpResp;
            if (reqLine.StartsWith("GET /configs ", StringComparison.Ordinal))
            {
                const string cfgBody = """{"mode":"rule","tun":{"enable":true,"device":"Mihomo"}}""";
                httpResp = $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {Encoding.UTF8.GetByteCount(cfgBody)}\r\nConnection: close\r\n\r\n{cfgBody}";
            }
            else
            {
                var c1Len = Encoding.UTF8.GetByteCount(chunk1).ToString("x");
                var c2Len = Encoding.UTF8.GetByteCount(chunk2).ToString("x");
                httpResp = $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{c1Len}\r\n{chunk1}\r\n{c2Len}\r\n{chunk2}\r\n0\r\n\r\n";
            }

            var respBytes = Encoding.UTF8.GetBytes(httpResp);
            await srv.WriteAsync(respBytes, pipeCts.Token);
            await srv.FlushAsync(pipeCts.Token);
            srv.Disconnect();
        }
    }, pipeCts.Token);

    var pipeEp = new ClashEndpoint(@"\\.\pipe\" + mockPipeName, string.Empty, "clash-verge-pipe", mockPipeName);
    var pipeMode = await ClashInspector.DetectClashModeAsync(pipeEp, isFlClash: false, pipeCts.Token);
    Assert(pipeMode == "rule", $"Clash 命名管道 /configs 应准确解析模式 rule（实际 {pipeMode}）", failures);

    var (pipeRulesOk, pipeRulesReason, pipeRules) = await ClashInspector.FetchRulesAsync(pipeEp, pipeCts.Token);
    Assert(pipeRulesOk && ClashInspector.ArePinnedRulesLoaded(pipeRules, WebRtcPolicies.Proxy),
        $"Clash 命名管道 /rules 应正确解码 chunked 响应并验过 16 条置顶规则（ok={pipeRulesOk}, reason={pipeRulesReason}, count={pipeRules.Count}）",
        failures);
    await serverTask;
}

if (failures.Count > 0)
{
    foreach (var failure in failures)
    {
        Console.Error.WriteLine(failure);
    }
    return 1;
}

Console.WriteLine("All Claude Desktop Guardian tests passed (baseline + integrated modules).");
return 0;

static void Assert(bool condition, string message, ICollection<string> failures)
{
    if (!condition)
    {
        failures.Add(message);
    }
}

static void AssertThrows<TException>(Action action, string message, ICollection<string> failures)
    where TException : Exception
{
    try
    {
        action();
        failures.Add(message);
    }
    catch (TException)
    {
    }
    catch (Exception ex)
    {
        failures.Add($"{message}（实际抛出 {ex.GetType().Name}）");
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

sealed class ExtendedFakeProbe : IEnvironmentProbe
{
    public string AdapterName { get; set; } = "Meta";
    public bool ProxyClientAlive { get; set; } = true;
    public bool ProxyPathSkipped { get; set; }
    public bool AdapterIsFakeIp { get; set; } = true;
    public string ExitIp { get; set; } = "203.0.113.10";
    public string ExitCountry { get; set; } = "US";
    public IReadOnlyList<string> ResolvedClaudeIps { get; set; } = new[] { "198.18.0.42" };
    public IReadOnlyList<string> PublicIpv6Routes { get; set; } = Array.Empty<string>();
    public string WfpPolicyState { get; set; } = "off";
    public string ClashRulesStatus { get; set; } = "ok";
    public string ClashRulesDetail { get; set; } = "全局模式";
    public IpReputationRecord? IpReputation { get; set; }
    public int IpDriftCount48h { get; set; }
    public bool HelperAlive { get; set; } = true;
    public bool FirewallApiOk { get; set; } = true;
    public int FirewallActiveRuleCount { get; set; }
    public IReadOnlyList<string> ActiveConnections { get; set; } = Array.Empty<string>();
    public IReadOnlyList<StunResult>? StunResultsOverride { get; set; }
    public bool? ClashRulesLoadedOverride { get; set; }
    public string? DnsProbeDetailOverride { get; set; }
    public bool SystemProxyConfigured { get; set; }
    public string SystemProxyUri { get; set; } = string.Empty;
    public string TunDirectExitIp { get; set; } = string.Empty;
    public string TunDirectExitCountry { get; set; } = string.Empty;
    public string TunDirectProbeDetail { get; set; } = string.Empty;

    public void ResetHealthy()
    {
        AdapterName = "Meta";
        ProxyClientAlive = true;
        ProxyPathSkipped = false;
        AdapterIsFakeIp = true;
        ExitIp = "203.0.113.10";
        ExitCountry = "US";
        ResolvedClaudeIps = new[] { "198.18.0.42" };
        PublicIpv6Routes = Array.Empty<string>();
        WfpPolicyState = "off";
        ClashRulesStatus = "ok";
        ClashRulesDetail = "全局模式";
        IpReputation = null;
        IpDriftCount48h = 0;
        HelperAlive = true;
        FirewallApiOk = true;
        FirewallActiveRuleCount = 0;
        ActiveConnections = Array.Empty<string>();
        StunResultsOverride = null;
        ClashRulesLoadedOverride = null;
        DnsProbeDetailOverride = null;
        SystemProxyConfigured = false;
        SystemProxyUri = string.Empty;
        TunDirectExitIp = string.Empty;
        TunDirectExitCountry = string.Empty;
        TunDirectProbeDetail = string.Empty;
    }

    public Task<NetworkSnapshot> CaptureNetworkAsync(
        GuardianConfig config,
        IReadOnlyList<ProcessInfo> protectedProcesses,
        bool full,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(new NetworkSnapshot(
            AdapterName,
            "Wintun Userspace Tunnel",
            "198.18.0.1",
            "198.18.0.2",
            ProxyPathSkipped ? string.Empty : ExitIp,
            ProxyPathSkipped ? string.Empty : ExitCountry,
            string.Empty,
            string.Empty,
            new[] { "198.18.0.2" },
            ProxyPathSkipped
                ? Array.Empty<StunResult>()
                : StunResultsOverride ?? new[] { new StunResult("stun.cloudflare.com", 3478, "ok", ExitIp, "ok") },
            ActiveConnections,
            PublicIpv6Routes.Count > 0,
            ProxyPathSkipped
                ? new Dictionary<string, string>()
                : new Dictionary<string, string> { ["api.anthropic.com"] = "401", ["claude.ai"] = "200" },
            ExitTimezone: "America/Los_Angeles",
            ExitWindowsTimezone: "Pacific Standard Time",
            CurrentWindowsTimezone: "Pacific Standard Time",
            AdapterGuid: "{11111111-2222-3333-4444-555555555555}",
            AdapterIsFakeIp: AdapterIsFakeIp,
            AdapterHasDefaultRoute: !string.IsNullOrEmpty(AdapterName),
            ProxyClientName: "Clash Verge",
            ProxyClientAlive: ProxyClientAlive,
            ProxyClientDetail: ProxyClientAlive ? "Clash Verge 运行中" : "Clash Verge 未运行",
            ExitIpSource: "cloudflare",
            ProxyPathSkipped: ProxyPathSkipped,
            ResolvedClaudeIps: ResolvedClaudeIps,
            DnsProbeDetail: DnsProbeDetailOverride ?? "claude.ai 解析测试",
            PublicIpv6Routes: PublicIpv6Routes,
            CurrentLocale: "en-US",
            ExpectedLocale: "en-US",
            ClientLanguage: "en-US",
            AsnOrg: "AS7922 Comcast Cable",
            AsnType: "Cable/DSL/ISP",
            AsnDetail: "ISP（AS7922 Comcast Cable）",
            ClashMode: "rule",
            ClashRulesStatus: ClashRulesStatus,
            ClashRulesDetail: ClashRulesDetail,
            ClashRulesLoaded: ClashRulesLoadedOverride ?? (ClashRulesStatus == "ok"),
            WfpPolicyState: WfpPolicyState,
            WfpPolicyDetail: $"WFP 状态：{WfpPolicyState}",
            IpReputation: IpReputation,
            IpDriftCount48h: IpDriftCount48h,
            PreviousExitIp: ExitIp,
            HelperAlive: HelperAlive,
            HelperDetail: HelperAlive ? "管理员助手在线" : "管理员助手离线",
            FirewallApiOk: FirewallApiOk,
            FirewallActiveRuleCount: FirewallActiveRuleCount,
            FirewallDetail: FirewallApiOk ? "防火墙就绪" : "防火墙不可读",
            SystemProxyConfigured: SystemProxyConfigured,
            SystemProxyUri: SystemProxyUri,
            TunDirectExitIp: TunDirectExitIp,
            TunDirectExitCountry: TunDirectExitCountry,
            TunDirectProbeDetail: TunDirectProbeDetail));
    }
}

sealed class FakeHelperExecutor : IHelperSystemExecutor
{
    public string Token { get; } = "fake-helper-token-1234567890abcdef";
    public string CurrentUserSid => "S-1-5-21-fake";
    public int CurrentProcessId => 4242;
    public string CurrentTimezone { get; set; } = "China Standard Time";
    public List<(string RuleName, string Group, string ProgramPath)> ActiveFirewallRules { get; } = new();
    public List<int> TerminatedPids { get; } = new();
    public List<string> DisabledIpv6Adapters { get; } = new();
    public int WfpRemovedCount { get; private set; }
    public string ClearedAllPrefix { get; private set; } = string.Empty;
    public int SimulatedRemainingAfterWfpKill { get; set; }
    public int ClearDelayMs { get; set; }

    public string GetExpectedToken() => Token;

    public IReadOnlyList<string> DiscoverClaudeExecutablePaths() =>
        new[] { @"C:\Users\Test\AppData\Local\AnthropicClaude\Claude.exe" };

    public bool IsAllowedClaudePath(string path) =>
        path.Contains("\\Claude\\", StringComparison.OrdinalIgnoreCase) ||
        path.Contains("\\AnthropicClaude\\", StringComparison.OrdinalIgnoreCase);

    public IReadOnlyList<ProcessInfo> FindCurrentUserClaudeProcesses() =>
        new[]
        {
            new ProcessInfo(1001, 1, "Claude.exe", @"C:\Users\Test\AppData\Local\Programs\Claude\Claude.exe", "S-1-5-21-fake"),
            new ProcessInfo(2002, 1, "Claude.exe", @"C:\Users\Other\AppData\Local\Programs\Claude\Claude.exe", "S-1-5-21-other")
        };

    public Task<string> ReadTimezoneAsync() => Task.FromResult(CurrentTimezone);

    public Task SetTimezoneAsync(string timezoneId)
    {
        CurrentTimezone = timezoneId;
        return Task.CompletedTask;
    }

    public HelperFirewallStatus QueryFirewallGroupStatus(string groupName)
    {
        var count = ActiveFirewallRules.Count(r => string.Equals(r.Group, groupName, StringComparison.OrdinalIgnoreCase));
        return new HelperFirewallStatus(true, count, $"mock group {groupName} rules={count}");
    }

    public async Task ClearFirewallGroupAsync(string groupName)
    {
        if (ClearDelayMs > 0)
        {
            await Task.Delay(ClearDelayMs);
        }

        ActiveFirewallRules.RemoveAll(r => string.Equals(r.Group, groupName, StringComparison.OrdinalIgnoreCase));
    }

    public Task ClearAllGuardianFirewallRulesAsync(string rulePrefix)
    {
        ClearedAllPrefix = rulePrefix;
        ActiveFirewallRules.RemoveAll(r => r.Group.StartsWith(rulePrefix, StringComparison.OrdinalIgnoreCase));
        return Task.CompletedTask;
    }

    public Task AddFirewallBlockRuleAsync(string ruleName, string groupName, string programPath)
    {
        ActiveFirewallRules.Add((ruleName, groupName, programPath));
        return Task.CompletedTask;
    }

    public Task<(int Terminated, int Remaining)> TerminateProcessesAsync(IReadOnlyList<int> processIds)
    {
        TerminatedPids.AddRange(processIds);
        return Task.FromResult((processIds.Count, 0));
    }

    public HelperWfpStatus QueryWfpDetailedSafe(string? adapterGuid, bool allowLoopback) =>
        new("active", "mock wfp active", 1);

    public HelperWfpStatus QueryWfpDetailed(string? adapterGuid, bool allowLoopback) =>
        new("active", "mock wfp active", 1);

    public Task<HelperWfpEnableResult> EnableWfpAsync(string? adapterGuid, IReadOnlyList<string> extraPaths, bool allowLoopback) =>
        Task.FromResult(new HelperWfpEnableResult(true, "mock wfp enabled", extraPaths.Count + 1, 1, SimulatedRemainingAfterWfpKill));

    public void DisableWfp() => WfpRemovedCount++;

    public Task FlushDnsAsync() => Task.CompletedTask;

    public Task DisableIpv6AdaptersAsync(IReadOnlyList<string> adapterNames)
    {
        DisabledIpv6Adapters.AddRange(adapterNames);
        return Task.CompletedTask;
    }
}

sealed class CountingSingleCheckProbe : IEnvironmentProbe, ISingleCheckProbe
{
    public int FullCaptureCount { get; private set; }
    public int SingleCaptureCount { get; private set; }
    public string LastSingleCheckId { get; private set; } = string.Empty;
    public IReadOnlyList<string> NextDnsIps { get; set; } = new[] { "198.18.0.42" };

    public Task<NetworkSnapshot> CaptureNetworkAsync(
        GuardianConfig config,
        IReadOnlyList<ProcessInfo> protectedProcesses,
        bool full,
        CancellationToken cancellationToken)
    {
        FullCaptureCount++;
        return Task.FromResult(new NetworkSnapshot(
            "Meta",
            "Wintun",
            "198.18.0.1",
            "198.18.0.2",
            "203.0.113.10",
            "US",
            string.Empty,
            string.Empty,
            new[] { "198.18.0.2" },
            new[] { new StunResult("stun.cloudflare.com", 3478, "ok", "203.0.113.10", "ok") },
            Array.Empty<string>(),
            false,
            new Dictionary<string, string> { ["api.anthropic.com"] = "401" },
            AdapterIsFakeIp: true,
            AdapterHasDefaultRoute: true,
            ProxyClientAlive: true,
            ResolvedClaudeIps: NextDnsIps,
            HelperAlive: true,
            FirewallApiOk: true));
    }

    public Task<NetworkSnapshot> CaptureSingleCheckAsync(
        NetworkSnapshot previous,
        string checkId,
        GuardianConfig config,
        IReadOnlyList<ProcessInfo> protectedProcesses,
        CancellationToken cancellationToken)
    {
        SingleCaptureCount++;
        LastSingleCheckId = checkId;
        var updated = string.Equals(checkId, GuardianCheckIds.Dns, StringComparison.OrdinalIgnoreCase)
            ? previous with { ResolvedClaudeIps = NextDnsIps, DnsProbeDetail = "单项复检完成" }
            : previous;
        return Task.FromResult(updated);
    }
}

sealed class CountingBrowserProbe : IWebRtcBrowserProbe
{
    private readonly WebRtcBrowserResult _result;
    public int ProbeCount { get; private set; }

    public CountingBrowserProbe(WebRtcBrowserResult result)
    {
        _result = result;
    }

    public Task<WebRtcBrowserResult> ProbeAsync(
        IReadOnlyList<string> stunUrls,
        CancellationToken cancellationToken)
    {
        ProbeCount++;
        return Task.FromResult(_result);
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

sealed class MockHttpHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;
    public int RequestCount { get; private set; }

    public MockHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
    {
        _responder = responder;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        RequestCount++;
        return Task.FromResult(_responder(request));
    }
}
