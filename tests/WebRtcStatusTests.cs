using ClaudeDesktopGuardian.App;
using ClaudeDesktopGuardian.Core;

internal static class WebRtcStatusTests
{
    internal static async Task RunAsync(ICollection<string> failures)
    {
        const string exitIp = "203.0.113.10";
        const string otherIp = "198.51.100.99";
        const string exitIpv6 = "2001:db8::10";
        const string lookupError = "STUN host lookup received error.";
        var config = new GuardianConfig(ExpectedExitIp: exitIp, ExpectedExitCountry: "US");
        var servers = new[]
        {
            (Host: "stun.cloudflare.com", Port: 3478),
            (Host: "stun.l.google.com", Port: 19302),
            (Host: "stun.miwifi.com", Port: 3478),
            (Host: "stun.chat.bilibili.com", Port: 3478)
        };
        var nativeResults = servers.Select(server =>
            new StunResult(server.Host, server.Port, "ok", exitIp, "IPv4 收到 STUN 映射地址")).ToArray();
        var errors = servers.Select(server =>
            new WebRtcIceError($"stun:{server.Host}:{server.Port}", 701, lookupError)).ToArray();
        var browser = new WebRtcBrowserResult(
            true,
            "complete",
            true,
            new[]
            {
                new WebRtcCandidate("probe.local", "mdns", "mDNS"),
                new WebRtcCandidate(exitIp, "public", "IPv4")
            },
            "ICE 候选收集完成",
            Errors: errors);
        var network = await new ExtendedFakeProbe().CaptureNetworkAsync(
            config, Array.Empty<ProcessInfo>(), true, CancellationToken.None);
        network = network with { StunResults = nativeResults };

        var cases = new (string Name, NetworkSnapshot Network, WebRtcBrowserResult Browser, CheckStatus Status)[]
        {
            ("完整 ICE 与原生 STUN 均匹配出口时，701 解析错误仅警告", network, browser, CheckStatus.Warn),
            ("没有 ICE 错误时仍通过", network, browser with { Errors = null }, CheckStatus.Ok),
            ("不支持 WebRTC 时仍未验证", network, browser with { Supported = false }, CheckStatus.Unknown),
            ("ICE 未完成时仍未验证", network, browser with { Complete = false }, CheckStatus.Unknown),
            ("ICE 状态不完整时仍未验证", network, browser with { Status = "incomplete" }, CheckStatus.Unknown),
            ("缺少 HTTP 出口基准时仍未验证", network with { ExitIp = string.Empty }, browser, CheckStatus.Unknown),
            ("原生 STUN 为空时仍未验证", network with { StunResults = Array.Empty<StunResult>() }, browser, CheckStatus.Unknown),
            ("原生 STUN 全部超时时仍未验证", network with
            {
                StunResults = nativeResults.Select(result => result with
                {
                    Status = "unknown", Address = string.Empty, Detail = "IPv4 STUN 超时"
                }).ToArray()
            }, browser, CheckStatus.Unknown),
            ("原生 STUN 部分超时时仍未验证", network with
            {
                StunResults = nativeResults.Select((result, index) => index == 0
                    ? result with { Status = "unknown", Address = string.Empty, Detail = "IPv4 STUN 超时" }
                    : result).ToArray()
            }, browser, CheckStatus.Unknown),
            ("原生 STUN 成功但缺地址时仍未验证", network with
            {
                StunResults = nativeResults.Select((result, index) => index == 0
                    ? result with { Address = string.Empty }
                    : result).ToArray()
            }, browser, CheckStatus.Unknown),
            ("只有 mDNS 候选时仍未验证", network, browser with
            {
                Candidates = new[] { new WebRtcCandidate("probe.local", "mdns", "mDNS") }
            }, CheckStatus.Unknown),
            ("其他 ICE 错误码仍未验证", network, browser with
            {
                Errors = new[] { errors[0] with { Code = 500 } }
            }, CheckStatus.Unknown),
            ("其他 701 错误仍未验证", network, browser with
            {
                Errors = new[] { errors[0] with { Text = "STUN server could not be reached" } }
            }, CheckStatus.Unknown),
            ("混合 ICE 错误仍未验证", network, browser with
            {
                Errors = errors.Append(errors[0] with { Code = 500 }).ToArray()
            }, CheckStatus.Unknown),
            ("错误对应的 STUN 服务未经原生验证时仍未验证", network, browser with
            {
                Errors = new[] { errors[0] with { Url = "stun:unverified.example:3478" } }
            }, CheckStatus.Unknown),
            ("原生 STUN 出口不一致优先判泄漏", network with
            {
                StunResults = nativeResults.Select((result, index) => index == 0
                    ? result with { Address = otherIp }
                    : result).ToArray()
            }, browser, CheckStatus.Fail),
            ("浏览器 IPv4 出口不一致优先判泄漏", network, browser with
            {
                Candidates = browser.Candidates.Append(new WebRtcCandidate(otherIp, "public", "IPv4")).ToArray()
            }, CheckStatus.Fail),
            ("浏览器 IPv6 出口不一致优先判泄漏", network, browser with
            {
                Candidates = browser.Candidates.Append(new WebRtcCandidate("2001:db8::99", "public", "IPv6")).ToArray()
            }, CheckStatus.Fail),
            ("IPv6 候选与原生 STUN 均匹配出口时也保留解析告警", network with
            {
                HasIpv6 = true,
                ExitIpv6 = exitIpv6,
                ExitIpv6Country = "US",
                StunResults = nativeResults.Select(result => result with { Address = exitIpv6 }).ToArray()
            }, browser with
            {
                Candidates = new[] { new WebRtcCandidate(exitIpv6, "public", "IPv6") }
            }, CheckStatus.Warn)
        };

        foreach (var testCase in cases)
        {
            var report = await EvaluateAsync(testCase.Network, testCase.Browser, config);
            var check = report.Checks.Single(result => result.Id == GuardianCheckIds.WebRtc);
            Assert(check.Status == testCase.Status, testCase.Name, failures);
            if (testCase.Status == CheckStatus.Warn)
            {
                Assert(!check.Blocking && check.Passed, testCase.Name + "，警告不得充当阻断失败", failures);
                Assert(!report.BlockingFailures.Any(result => result.Id == GuardianCheckIds.WebRtc),
                    testCase.Name + "，报告不得将其列为阻断失败", failures);
                Assert(check.Detail.Contains("出口一致", StringComparison.Ordinal) &&
                       check.Detail.Contains("解析告警", StringComparison.Ordinal),
                    testCase.Name + "，详情必须说明已验证部分和剩余告警", failures);
                foreach (var error in errors)
                {
                    Assert(check.Detail.Contains(error.Url, StringComparison.Ordinal),
                        testCase.Name + "，必须保留每个 STUN 服务的错误证据", failures);
                }
                var evidence = UiPresentationState.FormatCheckEvidence(check);
                Assert(evidence.Contains("警告", StringComparison.Ordinal) &&
                       evidence.Contains("非阻断项", StringComparison.Ordinal) &&
                       evidence.Contains("code=701", StringComparison.Ordinal) &&
                       evidence.Contains(lookupError, StringComparison.Ordinal),
                    testCase.Name + "，界面必须保留警告状态与原始错误", failures);
                Assert(ProtectionPolicyEvaluator.EvaluateLaunchGate(report, false, false).Allowed,
                    testCase.Name + "，健康环境不应被解析告警阻止启动", failures);
                Assert(report.CanRecover, testCase.Name + "，健康环境应允许显式恢复", failures);
            }
            else if (testCase.Status == CheckStatus.Fail)
            {
                var optionalReport = await EvaluateAsync(
                    testCase.Network, testCase.Browser, config with { AllowOptionalFailures = true });
                Assert(check.Blocking && report.HasConfirmedWebRtcLeak &&
                       !ProtectionPolicyEvaluator.EvaluateLaunchGate(report, false, true).Allowed &&
                       optionalReport.HasConfirmedWebRtcLeak,
                    testCase.Name + "，忽略设置和非关键降级均不得放行真实泄漏", failures);
            }
        }

        var egressMismatch = await EvaluateAsync(network, browser, config with { ExpectedExitIp = otherIp });
        Assert(egressMismatch.Checks.Single(check => check.Id == GuardianCheckIds.WebRtc).Status == CheckStatus.Warn &&
               !ProtectionPolicyEvaluator.EvaluateLaunchGate(egressMismatch, false, false).Allowed &&
               egressMismatch.BlockingFailures.Any(check => check.Id == GuardianCheckIds.EgressIp),
            "WebRTC 解析告警不得绕过独立的期望出口检查", failures);
    }

    private static Task<GuardianReport> EvaluateAsync(
        NetworkSnapshot network,
        WebRtcBrowserResult browser,
        GuardianConfig config) =>
        new GuardianCheckEngine(new SnapshotProbe(network), new FakeInspector(),
            new FakeBrowserProbe(browser), new FakeClock()).RunAsync(config, true, CancellationToken.None);

    private static void Assert(bool condition, string message, ICollection<string> failures)
    {
        if (!condition)
        {
            failures.Add(message);
        }
    }

    private sealed class SnapshotProbe(NetworkSnapshot network) : IEnvironmentProbe
    {
        public Task<NetworkSnapshot> CaptureNetworkAsync(
            GuardianConfig config,
            IReadOnlyList<ProcessInfo> protectedProcesses,
            bool full,
            CancellationToken cancellationToken) => Task.FromResult(network);
    }
}
