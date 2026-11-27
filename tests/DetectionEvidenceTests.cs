using ClaudeDesktopGuardian.Core;
using ClaudeDesktopGuardian.Helper;
using System.Net;
using System.IO;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net.Http;
using System.Text;
using System.Runtime.InteropServices;
using System.Text.Json;

internal static class DetectionEvidenceTests
{
    public static IReadOnlyList<DestinationRoute> HealthyRoutes { get; } =
        new[] { new DestinationRoute("203.0.113.10", 27, 27, true) };

    public static IReadOnlyDictionary<string, CollectionObservation> HealthyObservations() =>
        new[] { GuardianCheckIds.DefaultRoute, GuardianCheckIds.ActiveConnections, GuardianCheckIds.Dns,
                GuardianCheckIds.Ipv6, GuardianCheckIds.ClaudeDomains, GuardianCheckIds.EgressIp }
            .ToDictionary(id => id, _ => new CollectionObservation(true, DateTimeOffset.UtcNow));

    public static async Task RunAsync(List<string> failures)
    {
        void Check(bool condition, string message) { if (!condition) failures.Add(message); }
        var config = new GuardianConfig();
        Check(!config.TcpOnlyEnabled && !JsonSerializer.Deserialize<GuardianConfig>("{}")!.TcpOnlyEnabled,
            "新旧配置默认不启用 TCP-only");
        var healthy = await new ExtendedFakeProbe().CaptureNetworkAsync(config, Array.Empty<ProcessInfo>(), true, default);
        var probe = new SnapshotProbe(healthy);
        var engine = new GuardianCheckEngine(probe, new FakeInspector());
        async Task<CheckResult> Evaluate(string id, NetworkSnapshot snapshot, GuardianConfig? cfg = null)
        {
            probe.Snapshot = snapshot;
            return (await engine.RunAsync(cfg ?? config, true, default)).Checks.Single(check => check.Id == id);
        }
        var emptyDns = await Evaluate(GuardianCheckIds.Dns, healthy with { ResolvedClaudeIps = Array.Empty<string>(), DnsProbeDetail = "" });
        Check(emptyDns.Status == CheckStatus.Unknown && emptyDns.Blocking, "空 DNS 结果不得误绿");
        var emptyDnsDowngraded = await Evaluate(GuardianCheckIds.Dns,
            healthy with { ResolvedClaudeIps = Array.Empty<string>(), DnsProbeDetail = "" },
            config with { AllowOptionalFailures = true });
        Check(emptyDnsDowngraded.Status == CheckStatus.Warn && !emptyDnsDowngraded.Blocking,
            "开启可选降级时，DNS 兜底空结果应与 DNS 失败分支一致降级为 Warn");
        var malformedDns = await Evaluate(GuardianCheckIds.Dns, healthy with { ResolvedClaudeIps = new[] { "invalid" } });
        Check(malformedDns.Status == CheckStatus.Unknown, "非法 DNS 地址不得误绿");
        foreach (var id in new[] { GuardianCheckIds.ActiveConnections, GuardianCheckIds.Ipv6, GuardianCheckIds.DefaultRoute })
        {
            var observations = new Dictionary<string, CollectionObservation>(healthy.Observations!)
            { [id] = new(false, DateTimeOffset.UtcNow, "synthetic-native-error") };
            var result = await Evaluate(id, healthy with { Observations = observations });
            Check(result.Status == CheckStatus.Unknown && result.Blocking, id + " 读取失败必须 Unknown 并阻断");
            Check(result.Evidence["collection_error"] == "synthetic-native-error", id + " 应保留采集错误");
        }
        var emptyConnections = await Evaluate(GuardianCheckIds.ActiveConnections, healthy);
        Check(emptyConnections.Status == CheckStatus.Ok, "成功采集且无连接可通过");
        var udp = await Evaluate(GuardianCheckIds.ActiveConnections, healthy with
        { UdpEndpoints = new[] { new TransportEndpoint(1001, "UDP", "0.0.0.0", 12345) } });
        Check(udp.Evidence["udp_bound_endpoints"] == "1" && udp.Detail.Contains("不证明已经发送"),
            "UDP 端点不能冒充出站数据包");
        foreach (var (value, expected) in new[] { ("InvalidOperationException", CheckStatus.Unknown),
                     ("timeout", CheckStatus.Unknown), ("000", CheckStatus.Unknown), ("600", CheckStatus.Unknown),
                     ("200", CheckStatus.Ok), ("302", CheckStatus.Ok), ("401", CheckStatus.Ok),
                     ("403", CheckStatus.Warn), ("429", CheckStatus.Warn), ("500", CheckStatus.Warn) })
        {
            var result = await Evaluate(GuardianCheckIds.ClaudeDomains,
                healthy with { ClaudeHttps = new Dictionary<string, string> { ["api.anthropic.com"] = value } },
                config with { ClaudeDomains = new[] { "api.anthropic.com" } });
            Check(result.Status == expected, "HTTPS " + value + " 分类错误");
            if (expected == CheckStatus.Warn)
                Check(!result.Blocking && result.Passed, "HTTPS " + value + " 警告默认不得阻断启动");
        }
        probe.Snapshot = healthy with
        {
            ClaudeHttps = new Dictionary<string, string>
            {
                ["api.anthropic.com"] = "401",
                ["platform.claude.com"] = "200",
                ["claude.ai"] = "403",
                ["claude.com"] = "200",
                ["anthropic.com"] = "200"
            },
            ClashRulesStatus = "warn",
            ClashRulesDetail = "代理组非标准命名",
            IpReputation = new IpReputationRecord(DateTimeOffset.UtcNow, Score: 5, IsProxy: false, IsVpn: null, IsTor: false, IsHosting: false, BlacklistCount: 0)
        };
        var warnOnlyReport = await engine.RunAsync(
            config with { IpReputation = new IpReputationConfig("https://rep.test/{ip}", "", 25, 7) }, true, default);
        Check(warnOnlyReport.Checks.Single(c => c.Id == GuardianCheckIds.ClaudeDomains).Status == CheckStatus.Warn &&
              warnOnlyReport.Checks.Single(c => c.Id == GuardianCheckIds.ClashRules).Status == CheckStatus.Warn &&
              warnOnlyReport.Checks.Single(c => c.Id == GuardianCheckIds.IpRepProxy).Status == CheckStatus.Warn &&
              ProtectionPolicyEvaluator.EvaluateLaunchGate(warnOnlyReport, false, false).Allowed &&
              ProtectionPolicyEvaluator.Evaluate(warnOnlyReport, false, false).Action == ProtectionAction.None,
            "OptionalResult 产生的 Warn（含 claude.ai=403、Clash 告警、信誉缺字段）默认不得阻断安全启动或急停 Claude");
        var blockOnWarnReport = await engine.RunAsync(config with { BlockOnWarning = true }, true, default);
        Check(!ProtectionPolicyEvaluator.EvaluateLaunchGate(blockOnWarnReport, false, false).Allowed,
            "显式开启 BlockOnWarning 时，OptionalResult 的 Warn 应按配置阻断启动");
        var web401 = await Evaluate(GuardianCheckIds.ClaudeDomains,
            healthy with { ClaudeHttps = new Dictionary<string, string> { ["claude.ai"] = "401" } },
            config with { ClaudeDomains = new[] { "claude.ai" } });
        Check(web401.Status == CheckStatus.Warn && !web401.Blocking, "仅预期 API 401 可作为正常的需认证响应，且 401 警告默认不阻断");
        var partialHttps = await Evaluate(GuardianCheckIds.ClaudeDomains,
            healthy with { ClaudeHttps = new Dictionary<string, string> { ["api.anthropic.com"] = "200" } });
        Check(partialHttps.Status == CheckStatus.Unknown, "缺少必要域名响应不得误绿");
        var disabled = await Evaluate(GuardianCheckIds.TcpOnlyPolicy, healthy);
        Check(disabled.Status == CheckStatus.Skip && !disabled.Blocking, "TCP-only 默认关闭显示 Skip");
        foreach (var (state, expected) in new[] { ("active", CheckStatus.Ok), ("off", CheckStatus.Fail),
                     ("stale", CheckStatus.Fail), ("invalid", CheckStatus.Fail), ("unknown", CheckStatus.Unknown), ("", CheckStatus.Unknown) })
        {
            var result = await Evaluate(GuardianCheckIds.TcpOnlyPolicy, healthy with { TcpOnlyState = state },
                config with { TcpOnlyEnabled = true, AllowOptionalFailures = true });
            Check(result.Status == expected && result.Blocking, "TCP-only " + state + " 不可被可选降级设置绕过");
        }
        var oldHelper = await Evaluate(GuardianCheckIds.TcpOnlyPolicy, healthy with { TcpOnlyState = null },
            config with { TcpOnlyEnabled = true });
        Check(oldHelper.Status == CheckStatus.Unknown, "旧助手缺字段必须 Unknown");
        foreach (var effective in new bool?[] { false, null })
        {
            var result = await Evaluate(GuardianCheckIds.FirewallReadiness, healthy with { FirewallPolicyEffective = effective });
            Check(result.Status == (effective == false ? CheckStatus.Fail : CheckStatus.Unknown), "失效或未读取的防火墙策略不得通过");
        }
        var specificRoute = healthy with { DestinationRoutes = new[]
            { new DestinationRoute("203.0.113.11", 4, 27, true) }, AdapterHasDefaultRoute = true };
        Check((await Evaluate(GuardianCheckIds.DefaultRoute, specificRoute)).Status == CheckStatus.Fail,
            "更具体的物理接口路由必须覆盖看似正常的默认路由判定");
        var singleBaseline = await engine.RunAsync(config, true, default);
        probe.Snapshot = specificRoute;
        var singleUpdated = await engine.RunSingleCheckAsync(singleBaseline, GuardianCheckIds.Dns, config, default);
        Check(singleUpdated.Checks.Single(check => check.Id == GuardianCheckIds.DefaultRoute).Status == CheckStatus.Fail,
            "单项复检刷新依赖后不得保留已失效路由的旧绿色结果");
        var observed = DateTimeOffset.Parse("2026-11-01T00:00:00Z");
        var cached = new Dictionary<string, CollectionObservation>(healthy.Observations!)
        { [GuardianCheckIds.Dns] = new(true, observed, IsCached: true) };
        var cachedDns = await Evaluate(GuardianCheckIds.Dns, healthy with { Observations = cached });
        Check(cachedDns.ObservedAt == observed && cachedDns.IsCached && cachedDns.Evidence["cached"] == "true",
            "复用证据应保留真实观测时间，不能刷新成当前时间");
        Check(!EvidenceFreshness.NeedsEgressRefresh(observed.AddSeconds(59), new(true, observed), "203.0.113.10") &&
              EvidenceFreshness.NeedsEgressRefresh(observed.AddSeconds(60), new(true, observed), "203.0.113.10"),
            "同一网卡的出口基线必须最多 60 秒刷新，不能复用到 30 分钟");
        Check(EvidenceFreshness.NeedsEgressRefresh(observed, new(false, observed), "203.0.113.10"), "失败的出口采集必须重试");
        Check(EvidenceFreshness.EgressBaselineChanged("203.0.113.10", "US", "203.0.113.11", "US") &&
              EvidenceFreshness.EgressBaselineChanged("203.0.113.10", "US", "203.0.113.10", "JP"),
            "同网卡换出口 IP 或国家必须使依赖缓存失效");
        Check(!EvidenceFreshness.EgressBaselineChanged("203.0.113.10", "US", "", ""),
            "瞬时出口采集失败（空 IP）不得误判为换出口而清空全量缓存");
        probe.Snapshot = healthy;
        var beforeTimeout = await engine.RunAsync(config, true, default);
        var afterTimeout = EvidenceFreshness.AfterTimeout(beforeTimeout, 45_001);
        Check(afterTimeout.ObservedAt == beforeTimeout.ObservedAt && afterTimeout.Network.LastCycleTimedOut &&
              afterTimeout.Checks.All(check => check.Status == CheckStatus.Skip || check.Status == CheckStatus.Unknown && check.IsCached),
            "超时不能把旧绿证据显示为新鲜，不能重写最后成功时间");
        var afterSecondTimeout = EvidenceFreshness.AfterTimeout(afterTimeout, 45_002);
        Check(afterSecondTimeout.Checks.All(check =>
            check.Status == CheckStatus.Skip ||
            check.Detail.IndexOf("本轮检查超时", StringComparison.Ordinal) ==
            check.Detail.LastIndexOf("本轮检查超时", StringComparison.Ordinal)),
            "连续超时不得重复拼接旧证据前缀");
        var singleFailed = EvidenceFreshness.AfterSingleCheckFailure(beforeTimeout, GuardianCheckIds.Asn, 25_001, true);
        Check(singleFailed.Checks.Single(check => check.Id == GuardianCheckIds.Asn).Status == CheckStatus.Unknown &&
              singleFailed.Checks.Single(check => check.Id == GuardianCheckIds.EgressIp).Status == CheckStatus.Ok &&
              ProtectionPolicyEvaluator.EvaluateLaunchGate(singleFailed, false, false).Allowed &&
              ProtectionPolicyEvaluator.Evaluate(singleFailed, false, false).Action == ProtectionAction.None,
            "可选检查单项复检超时只应影响目标项，不得污染硬检查或急停 Claude");
        Check(!ProtectionPolicyEvaluator.EvaluateLaunchGate(afterTimeout, false, false).Allowed,
            "超时后旧证据不能继续允许启动");
        var confirmed = beforeTimeout with { Checks = beforeTimeout.Checks.Select(check => check.Id == GuardianCheckIds.WebRtc
            ? check with { Status = CheckStatus.Fail, Blocking = true } : check).ToArray() };
        Check(EvidenceFreshness.AfterTimeout(confirmed, 45_001).HasConfirmedWebRtcLeak &&
              EvidenceFreshness.AfterSingleCheckFailure(confirmed, GuardianCheckIds.WebRtc, 25_001, true).HasConfirmedWebRtcLeak,
            "采集超时不得把确认的 WebRTC 泄漏降级为 Unknown");
        var browser = new CountingBrowserProbe(new(true, "complete", true, Array.Empty<WebRtcCandidate>(), "synthetic"));
        var contextEngine = new GuardianCheckEngine(probe, new FakeInspector(), browser);
        var initialContext = await contextEngine.RunAsync(config, true, default);
        probe.Snapshot = healthy with { ContextChanged = true, ExitIp = "203.0.113.11", NetworkContext = "new-synthetic-context" };
        var newContext = await contextEngine.RunSingleCheckAsync(initialContext, GuardianCheckIds.Dns, config, default);
        Check(browser.ProbeCount == 2 && newContext.Checks.Count == 24, "网络上下文变化时单项复检须刷新 ICE 依赖并保留 24 项");
        probe.Snapshot = specificRoute;
        await contextEngine.RunAsync(config, true, default);
        Check(browser.ProbeCount == 2, "路由未通过时不得发起浏览器外网 ICE 探测");

        var native = new SyntheticNativeApi();
        var collector = new NativeNetworkEvidence(native);
        var processes = new[] { new ProcessInfo(1001, 1, "Claude.exe", "synthetic", "synthetic-user") };
        var connectionEvidence = collector.CaptureConnections(processes, observed);
        Check(connectionEvidence.Observation.Succeeded && connectionEvidence.Tcp.Count == 2 && connectionEvidence.Udp.Count == 2,
            "应采集当前用户 Claude 的 IPv4/IPv6 TCP 与 UDP 端点并排除其他 PID");
        Check(connectionEvidence.Tcp.Any(endpoint => endpoint.RemoteAddress.Contains(':')),
            "IPv6 TCP 地址解析错误");
        native.ResizeOnce = true;
        Check(collector.CaptureConnections(processes, observed).Observation.Succeeded, "原生缓冲区增长应重试");
        native.TableError = 5;
        Check(!collector.CaptureConnections(processes, observed).Observation.Succeeded, "原生错误不能吞成成功空表");
        native.TableError = 0;
        native.Empty = true;
        var trulyEmpty = collector.CaptureConnections(processes, observed);
        Check(trulyEmpty.Observation.Succeeded && trulyEmpty.Tcp.Count == 0, "成功的空端点表必须可区别于失败");
        native.RouteError = true;
        Check(!collector.CaptureRoutes(observed).Observation.Succeeded, "路由采集异常应保留失败状态");
        Check(!collector.InspectRoute(IPAddress.Parse("2001:db8::1"), 27).Succeeded, "最佳路由异常应保留失败状态");
        native.RouteError = false;
        Check(collector.InspectRoute(IPAddress.Parse("203.0.113.1"), 27).Matches, "原生最佳路由应匹配预期接口");
        native.BestIndex = 4;
        Check(!collector.InspectRoute(IPAddress.Parse("203.0.113.1"), 27).Matches, "物理更具体路由不能通过");
        var routeGuard = new WindowsEnvironmentProbe.ProbeRouteContext(collector, 27, 27, true, new());
        using (var listener = new TcpListener(IPAddress.Loopback, 0))
        {
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var client = WindowsEnvironmentProbe.CreateHttpClient(AddressFamily.InterNetwork, false, routeGuard.Validate);
            try
            {
                await client.GetAsync($"http://127.0.0.1:{port}/");
                failures.Add("TUN 目标路由不匹配应在连接前拒绝探针");
            }
            catch (HttpRequestException) { }
            Check(!listener.Pending(), "目标接口不匹配时不能向本地测试服务发送 TCP 建连");
            native.BestIndex = 27;
            var serve = Task.Run(async () =>
            {
                using var peer = await listener.AcceptTcpClientAsync();
                await using var stream = peer.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, true);
                while (!string.IsNullOrEmpty(await reader.ReadLineAsync())) { }
                await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"));
            });
            Check((await client.GetAsync($"http://127.0.0.1:{port}/")).StatusCode == HttpStatusCode.OK,
                "实际路由匹配后探针应能访问隔离本地服务");
            await serve.WaitAsync(TimeSpan.FromSeconds(5));
        }
        native.RouteError = true;
        routeGuard.Validate(IPAddress.Loopback, true);
        Check(routeGuard.Results.Any(route => !route.Matches), "系统代理本地入口放行与 TUN 直连核验需分开");
        native.RouteError = false;
        var table = collector.CaptureRoutes(observed);
        var key = NativeNetworkEvidence.ContextKey(new[] { "tun:27", "dns:synthetic" }, table, "proxy:local");
        Check(key != NativeNetworkEvidence.ContextKey(new[] { "tun:28", "dns:synthetic" }, table, "proxy:local"), "TUN 重建应改变网络上下文");
        Check(key != NativeNetworkEvidence.ContextKey(new[] { "tun:27", "dns:changed" }, table, "proxy:local"), "DNS 变化应改变网络上下文");
        Check(key != NativeNetworkEvidence.ContextKey(new[] { "tun:27", "dns:synthetic" }, table, "proxy:changed"), "代理变化应改变网络上下文");
        Check(!WindowsEnvironmentProbe.HasAdapterPublicIpv6Route(true, false, 27,
                  new[] { new NativeRoute(27, IPAddress.Parse("fdfe:dcba:9876::"), 64, 0) }),
            "仅有 ULA 地址而无公网/默认 IPv6 路由的 TUN 不应误判为启用公网 IPv6");
        Check(WindowsEnvironmentProbe.HasAdapterPublicIpv6Route(true, false, 27,
                  new[] { new NativeRoute(27, IPAddress.IPv6Any, 0, 0) }) &&
              WindowsEnvironmentProbe.HasAdapterPublicIpv6Route(true, true, 27, Array.Empty<NativeRoute>()),
            "存在 IPv6 网关或默认/公网路由的 TUN 必须识别为启用 IPv6");
        Check(!WindowsEnvironmentProbe.ShouldRequireTunRoute(IPAddress.Parse("127.0.0.1")) &&
              !WindowsEnvironmentProbe.ShouldRequireTunRoute(IPAddress.Parse("192.168.1.10")) &&
              !WindowsEnvironmentProbe.ShouldRequireTunRoute(IPAddress.Parse("10.0.0.5")) &&
              !WindowsEnvironmentProbe.ShouldRequireTunRoute(IPAddress.Parse("172.16.0.2")) &&
              !WindowsEnvironmentProbe.ShouldRequireTunRoute(IPAddress.Parse("169.254.1.1")) &&
              !WindowsEnvironmentProbe.ShouldRequireTunRoute(IPAddress.Parse("fe80::1")) &&
              !WindowsEnvironmentProbe.ShouldRequireTunRoute(IPAddress.Parse("fdfe:dcba:9876::1")) &&
              WindowsEnvironmentProbe.ShouldRequireTunRoute(IPAddress.Parse("198.18.0.42")) &&
              WindowsEnvironmentProbe.ShouldRequireTunRoute(IPAddress.Parse("1.1.1.1")) &&
              WindowsEnvironmentProbe.ShouldRequireTunRoute(IPAddress.Parse("203.0.113.10")) &&
              WindowsEnvironmentProbe.ShouldRequireTunRoute(IPAddress.Parse("2001:db8::1")),
            "目标最佳路由校验应排除回环/私网/链路本地，保留 Fake-IP 与公网目标");
        Check(WindowsFirewallPolicyStore.IsLocalPolicyStateEffective(0) &&
              WindowsFirewallPolicyStore.IsLocalPolicyStateEffective(2) &&
              !WindowsFirewallPolicyStore.IsLocalPolicyStateEffective(1) &&
              !WindowsFirewallPolicyStore.IsLocalPolicyStateEffective(99),
            "防火墙有效策略应兼容阻止所有传入连接(2)，但拒绝组策略覆盖(1)与未知值");

        var firewall = new MemoryFirewall();
        using var installation = new SyntheticInstallation();
        var installedPaths = new[] { installation.Version1 };
        var executor = new WindowsHelperSystemExecutor(firewall, () =>
            new ClaudeInstallation("", "", "", installedPaths, "", null));
        var group = "ClaudeDesktopGuardian.synthetic.TcpOnly";
        var enabled = await executor.EnableTcpOnlyAsync(group);
        Check(enabled.State == "active", "TCP-only 应能创建并读回规则");
        var expectedRule = firewall.Rules.Single();
        Check(expectedRule.LocalUsers.StartsWith("O:LSD:(A;;CC;;;", StringComparison.Ordinal),
            "TCP-only 托管规则 LocalUserAuthorizedList 必须带 O:LS 属主前缀");
        Check(expectedRule.Protocol == 17 && expectedRule.Profiles == 7 && expectedRule.RemotePorts == "*" && !expectedRule.InterfaceRestricted,
            "TCP-only 必须封禁全部出站 UDP 端口/接口/配置");
        Check(WindowsHelperSystemExecutor.RuleMatches(
                  expectedRule with { LocalUsers = expectedRule.LocalUsers.ToLowerInvariant() }, expectedRule),
            "LocalUsers SDDL 大小写规范化变化应兼容");
        Check((await executor.EnableTcpOnlyAsync(group)).State == "active" && firewall.Rules.Count == 1,
            "重复启用 TCP-only 必须先清旧规则再写入，避免 COM 重复同名规则导致 stale");
        var mutations = new Func<FirewallRuleEvidence, FirewallRuleEvidence>[]
        {
            rule => rule with { Enabled = false }, rule => rule with { Direction = 1 },
            rule => rule with { Action = 1 }, rule => rule with { Protocol = 6 }, rule => rule with { Profiles = 4 },
            rule => rule with { RemotePorts = "443" }, rule => rule with { LocalPorts = "443" },
            rule => rule with { RemoteAddresses = "203.0.113.1" }, rule => rule with { LocalAddresses = "127.0.0.1" },
            rule => rule with { InterfaceTypes = "Wireless" }, rule => rule with { InterfaceRestricted = true },
            rule => rule with { Application = "proxy-core.exe" }, rule => rule with { PackageSid = "other-package" },
            rule => rule with { LocalUsers = "other-user" }, rule => rule with { ServiceName = "other-service" },
            rule => rule with { RemoteUsers = "restricted-user" }, rule => rule with { RemoteMachines = "restricted-machine" },
            rule => rule with { SecureFlags = 1 }
        };
        foreach (var mutate in mutations)
        {
            firewall.Rules[0] = mutate(expectedRule);
            Check(executor.QueryTcpOnlyStatus(group).State == "stale", "规则属性篡改必须触发 stale");
        }
        Check((await executor.EnableTcpOnlyAsync(group)).State == "active" && firewall.Rules.Count == 1,
            "显式刷新应能幂等修复被篡改的同名托管规则");
        installedPaths = new[] { installation.Version2 };
        Check(executor.QueryTcpOnlyStatus(group).State == "stale", "Claude 升级路径改变应检测过期");
        Check((await executor.EnableTcpOnlyAsync(group)).State == "active", "显式刷新应覆盖新 Claude 安装身份");
        firewall.Effective = false;
        Check(executor.QueryTcpOnlyStatus(group).State == "invalid", "防火墙配置关闭/策略覆盖不得假绿");
        firewall.Readable = false;
        Check(executor.QueryTcpOnlyStatus(group).State == "unknown", "防火墙查询失败必须 Unknown");
        firewall.Readable = true;
        firewall.Effective = true;
        firewall.Rules.Add(expectedRule with { Name = "manual-user-rule", Protocol = 6 });
        await executor.DisableTcpOnlyAsync(group);
        Check(firewall.Rules.Single().Name == "manual-user-rule", "关闭策略必须保留手工规则");
        Check(executor.QueryTcpOnlyStatus(group).State == "off", "关闭 TCP-only 应显示 off");
        Check((await executor.EnableTcpOnlyAsync(group)).State == "active", "保存的设置可在下次启动重建规则");
        var msixStore = new MemoryFirewall();
        var msix = new WindowsHelperSystemExecutor(msixStore, () =>
            new ClaudeInstallation("Claude_SyntheticIdentity", "", "", installedPaths, "", null));
        Check((await msix.EnableTcpOnlyAsync(group)).State == "active" && msixStore.Rules.Count == 2 &&
              msixStore.Rules.Any(rule => rule.Application == "" && rule.PackageSid.StartsWith("S-1-15-2-")),
            "MSIX 包 SID 与 EXE 身份必须同时覆盖");
        var blockGroup = "ClaudeDesktopGuardian.synthetic";
        var blockRuleName = blockGroup + "." + HelperCommandDispatcher.HashPath(installation.Version2);
        await msix.AddFirewallBlockRuleAsync(blockRuleName, blockGroup, installation.Version2);
        await msix.AddFirewallPackageBlockRuleAsync(blockGroup);
        var emergencyRules = msixStore.Rules.Where(rule => rule.Group == blockGroup).ToArray();
        Check(emergencyRules.Length == 2 &&
              emergencyRules.All(rule => rule.Protocol == 256 && rule.Direction == 2 && rule.Action == 0 &&
                                         rule.Profiles == 7 && rule.LocalPorts == "" && rule.RemotePorts == "" &&
                                         rule.LocalUsers.StartsWith("O:LSD:(A;;CC;;;", StringComparison.Ordinal)) &&
              emergencyRules.Any(rule => rule.Application == installation.Version2 && rule.PackageSid == "") &&
              emergencyRules.Any(rule => rule.Application == "" && rule.PackageSid.StartsWith("S-1-15-2-")),
            "紧急防火墙阻断应通过 COM 写入全协议(256)且覆盖 EXE 与 MSIX 包身份");
        msixStore.Rules.Add(emergencyRules[0] with { Name = "manual-block-rule" });
        await msix.ClearFirewallGroupAsync(blockGroup);
        Check(msixStore.Rules.Count(rule => rule.Group == blockGroup) == 1 &&
              msixStore.Rules.Single(rule => rule.Group == blockGroup).Name == "manual-block-rule" &&
              msixStore.Rules.Count(rule => rule.Group == group) == 2,
            "清理紧急阻断组必须移除托管阻断规则，同时保留手工规则与 TCP-only 组规则");

        var fake = new FakeHelperExecutor { IncludeEmptySidProcess = true };
        var dispatcher = new HelperCommandDispatcher(fake);
        async Task<JsonElement> Command(string name, string? token = null)
        {
            var response = await dispatcher.HandleLineAsync(JsonSerializer.Serialize(new
            { token = token ?? fake.Token, command = name, paths = new[] { "arbitrary-proxy.exe" } }));
            return JsonSerializer.SerializeToElement(response);
        }
        Check(!(await Command("tcp-only-enable", "wrong-token")).GetProperty("ok").GetBoolean(), "TCP-only 命令必须认证");
        fake.TcpOnlyState = "active";
        Check((await Command("tcp-only-status")).GetProperty("tcpOnlyState").GetString() == "stale",
            "助手重启后需要重验旧会话，不能沿用 active");
        var enableResp = await Command("tcp-only-enable");
        Check(enableResp.GetProperty("ok").GetBoolean() && enableResp.GetProperty("error").GetString() == "",
            "认证启用流程应读回、确认退出且成功响应不带错误文案");
        Check(fake.TerminatedPids.Contains(1001) && fake.TerminatedPids.Contains(1003) && !fake.TerminatedPids.Contains(2002),
            "应终止当前用户（含空 SID 子进程）Claude 树，绝不触碰其他用户进程");
        var disableResp = await Command("tcp-only-disable");
        Check(disableResp.GetProperty("ok").GetBoolean() && disableResp.GetProperty("error").GetString() == "",
            "关闭命令应读回 off 且成功响应不带错误文案");
        fake.TcpOnlyRemaining = 1;
        Check(!(await Command("tcp-only-enable")).GetProperty("ok").GetBoolean(), "旧 Claude 会话未退出时必须拒绝宣称启用完成");

        // WFP canonical target resolution: discovered install paths take precedence over runtime junction/extra paths
        var discoveredWfp = new[]
        {
            @"C:\Program Files\WindowsApps\Claude_6.28899.6.0_x64__pzs8sxrjxfjjc\app\claude.exe",
            @"C:\Program Files\WindowsApps\Claude_6.28899.6.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe"
        };
        var runtimeExtraWfp = new[]
        {
            @"D:\WindowsApps\Claude_6.28899.6.0_x64__pzs8sxrjxfjjc\app\claude.exe",
            @"C:\Users\Me\AppData\Roaming\Claude\child.exe"
        };
        var resolvedCanonical = ClaudeInstallDiscovery.ResolveWfpTargetPaths(discoveredWfp, runtimeExtraWfp, _ => true);
        Check(resolvedCanonical.SequenceEqual(discoveredWfp),
            "已发现安装目录时，WFP 目标路径必须与查询阶段保持一致，不得拼接运行时/卷挂载点重复路径导致假 stale");
        var resolvedFallback = ClaudeInstallDiscovery.ResolveWfpTargetPaths(
            Array.Empty<string>(),
            new[] { installation.Version1, @"C:\Windows\System32\notepad.exe" },
            path => path.Contains(@"\Claude\", StringComparison.OrdinalIgnoreCase));
        Check(resolvedFallback.SequenceEqual(new[] { installation.Version1 }),
            "仅在标准目录未发现安装时才回退使用受白名单过滤的运行时路径");

        // Auto-refresh stale WFP on reconnect + one-click recovery policy refresh gates
        var strictCfg = config with { WfpStrictEnabled = true, TcpOnlyEnabled = true };
        var staleWfpReport = new GuardianReport(
            DateTimeOffset.UtcNow,
            Array.Empty<CheckResult>(),
            healthy with
            {
                AdapterGuid = "{11111111-2222-3333-4444-555555555555}",
                HelperAlive = true,
                ProxyPathSkipped = false,
                WfpPolicyState = "stale",
                TcpOnlyState = "stale"
            },
            Array.Empty<ProcessInfo>());
        Check(ProtectionPolicyEvaluator.ShouldAutoRefreshStaleWfp(strictCfg, staleWfpReport),
            "严格 WFP 在 TUN 恢复在线且无运行中 Claude 时，应自动刷新因网卡重建导致的 stale WFP");
        Check(!ProtectionPolicyEvaluator.ShouldAutoRefreshStaleWfp(
                strictCfg,
                staleWfpReport with { Network = staleWfpReport.Network with { WfpPolicyState = "off" } }),
            "手动关闭 WFP（off）时后台不得擅自重新启用");
        Check(!ProtectionPolicyEvaluator.ShouldAutoRefreshStaleWfp(
                strictCfg,
                staleWfpReport with { ProtectedProcesses = new[] { new ProcessInfo(1001, 4, "Claude.exe", installation.Version1, "S-1-5-21-1") } }),
            "Claude 运行中时后台不得静默重绑 WFP 以免意外杀进程");
        var recoveryRefresh = ProtectionPolicyEvaluator.NeedsRecoveryPolicyRefresh(strictCfg, staleWfpReport);
        Check(recoveryRefresh.RefreshWfp && recoveryRefresh.RefreshTcpOnly,
            "点击解除阻断时应识别过期的 WFP 与 TCP-only 并自动刷新复检");
        var recoveryOffWfp = ProtectionPolicyEvaluator.NeedsRecoveryPolicyRefresh(
            strictCfg,
            staleWfpReport with { Network = staleWfpReport.Network with { WfpPolicyState = "off", TcpOnlyState = "active" } });
        Check(recoveryOffWfp.RefreshWfp && !recoveryOffWfp.RefreshTcpOnly,
            "严格 WFP 解除阻断时若 WFP 为 off 也应自动重建，而 active 的 TCP-only 无需重复刷新");
        var recoveryOffline = ProtectionPolicyEvaluator.NeedsRecoveryPolicyRefresh(
            strictCfg,
            staleWfpReport with { Network = staleWfpReport.Network with { HelperAlive = false } });
        Check(!recoveryOffline.RefreshWfp && !recoveryOffline.RefreshTcpOnly,
            "管理员助手离线时不得宣称可执行策略刷新");
    }

    private sealed class SnapshotProbe(NetworkSnapshot snapshot) : IEnvironmentProbe, ISingleCheckProbe
    {
        public NetworkSnapshot Snapshot { get; set; } = snapshot;
        public Task<NetworkSnapshot> CaptureNetworkAsync(GuardianConfig config, IReadOnlyList<ProcessInfo> processes,
            bool full, CancellationToken token) => Task.FromResult(Snapshot);
        public Task<NetworkSnapshot> CaptureSingleCheckAsync(NetworkSnapshot previous, string id, GuardianConfig config,
            IReadOnlyList<ProcessInfo> processes, CancellationToken token) => Task.FromResult(Snapshot);
    }

    private sealed class MemoryFirewall : IFirewallPolicyStore
    {
        public List<FirewallRuleEvidence> Rules { get; } = new();
        public bool Readable { get; set; } = true;
        public bool Effective { get; set; } = true;
        public FirewallPolicyEvidence Read(string group) => new(Readable, Effective,
            Rules.Where(rule => rule.Group == group).ToArray(), "synthetic policy");
        // Append without auto-dedup to expose duplicate-name issues if caller forgets to remove first
        public void Add(FirewallRuleEvidence rule) => Rules.Add(rule);
        public void Remove(string name)
        {
            var index = Rules.FindIndex(rule => rule.Name == name);
            if (index >= 0) Rules.RemoveAt(index);
        }
    }

    private sealed class SyntheticInstallation : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "guardian-evidence-" + Guid.NewGuid().ToString("N"));
        public string Version1 => Path.Combine(_root, "Claude", "app-1", "Claude.exe");
        public string Version2 => Path.Combine(_root, "Claude", "app-2", "Claude.exe");
        public SyntheticInstallation()
        {
            foreach (var path in new[] { Version1, Version2 })
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllText(path, "synthetic executable fixture");
            }
        }
        public void Dispose() => Directory.Delete(_root, true);
    }

    private sealed class SyntheticNativeApi : INativeNetworkApi
    {
        public uint TableError { get; set; }
        public bool Empty { get; set; }
        public bool ResizeOnce { get; set; }
        public bool RouteError { get; set; }
        public int BestIndex { get; set; } = 27;
        public uint ReadTransportTable(bool udp, int family, IntPtr buffer, ref int size)
        {
            if (TableError != 0) return TableError;
            var rowSize = udp ? family == 2 ? 12 : 28 : family == 2 ? 24 : 56;
            var bytes = new byte[4 + (Empty ? 0 : 2) * rowSize];
            if (buffer == IntPtr.Zero) { size = bytes.Length; return 122; }
            if (ResizeOnce) { ResizeOnce = false; size = bytes.Length * 2; return 122; }
            if (size < bytes.Length) { size = bytes.Length; return 122; }
            BitConverter.GetBytes(Empty ? 0 : 2).CopyTo(bytes, 0);
            if (!Empty)
            {
                for (var index = 0; index < 2; index++)
                {
                    var offset = 4 + index * rowSize;
                    BitConverter.GetBytes(index == 0 ? 1001 : 2002).CopyTo(bytes, offset + rowSize - 4);
                    if (!udp)
                    {
                        BitConverter.GetBytes((int)TcpState.Established).CopyTo(bytes, offset + (family == 2 ? 0 : 48));
                        IPAddress.Parse(family == 2 ? "203.0.113.10" : "2001:db8::10").GetAddressBytes()
                            .CopyTo(bytes, offset + (family == 2 ? 12 : 24));
                        BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)443)).CopyTo(bytes, offset + (family == 2 ? 16 : 44));
                    }
                }
            }
            Marshal.Copy(bytes, 0, buffer, bytes.Length);
            size = bytes.Length;
            return 0;
        }
        public IReadOnlyList<NativeRoute> ReadRoutes() => RouteError ? throw new InvalidOperationException("synthetic error")
            : new[] { new NativeRoute(27, IPAddress.Any, 0, 0) };
        public int BestRoute(IPAddress destination) => RouteError ? throw new InvalidOperationException("synthetic error") : BestIndex;
    }
}
