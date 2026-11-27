using ClaudeDesktopGuardian.Core;

namespace ClaudeDesktopGuardian.App;

internal sealed record ProtectionBadgeState(
    string Label,
    string BackgroundResourceKey,
    string ForegroundResourceKey);

internal sealed record MainWindowUiDecision(
    ProtectionBadgeState Badge,
    bool CanLaunchClaude,
    string LaunchGateReason,
    bool CanRecoverNow,
    string TripReasonDisplay,
    string ExitPathSummary);

/// <summary>
/// Pure, UI-thread-independent presentation and gate mapper for MainWindow.
/// Shared by live WPF rendering and automated WPF state/color/gate tests.
/// </summary>
internal static class UiPresentationState
{
    public static readonly IReadOnlyList<string> RequiredStatusBrushKeys = new[]
    {
        "StatusOkBrush",
        "StatusOkBackgroundBrush",
        "StatusWarnBrush",
        "StatusWarnBackgroundBrush",
        "StatusErrorBrush",
        "StatusErrorBackgroundBrush",
        "StatusUnknownBrush",
        "StatusUnknownBackgroundBrush",
        "StatusSkipBrush",
        "AccentBrush",
        "AccentHoverBrush",
        "MutedBrush"
    };

    public static ProtectionBadgeState ComputeBadge(
        GuardianReport? report,
        bool blocked,
        bool ignoreWebRtc)
    {
        if (blocked)
        {
            return new ProtectionBadgeState("已阻断", "StatusWarnBackgroundBrush", "StatusWarnBrush");
        }

        if (report is null)
        {
            return new ProtectionBadgeState("检查中", "StatusUnknownBackgroundBrush", "StatusUnknownBrush");
        }

        if (ProtectionPolicyEvaluator.HasEffectiveUiStatus(report, CheckStatus.Fail, ignoreWebRtc))
        {
            return new ProtectionBadgeState("异常", "StatusErrorBackgroundBrush", "StatusErrorBrush");
        }

        if (ProtectionPolicyEvaluator.HasEffectiveUiStatus(report, CheckStatus.Warn, ignoreWebRtc))
        {
            return new ProtectionBadgeState("注意", "StatusWarnBackgroundBrush", "StatusWarnBrush");
        }

        if (ProtectionPolicyEvaluator.HasEffectiveUiStatus(report, CheckStatus.Unknown, ignoreWebRtc))
        {
            return new ProtectionBadgeState("未验证", "StatusUnknownBackgroundBrush", "StatusUnknownBrush");
        }

        return new ProtectionBadgeState("正常", "StatusOkBackgroundBrush", "StatusOkBrush");
    }

    public static MainWindowUiDecision Evaluate(
        GuardianReport? report,
        bool blocked,
        bool ignoreWebRtc,
        string? existingTripReason = null)
    {
        var badge = ComputeBadge(report, blocked, ignoreWebRtc);
        var launchGate = ProtectionPolicyEvaluator.EvaluateLaunchGate(report, blocked, ignoreWebRtc);
        var effectiveFailures = report is null
            ? Array.Empty<CheckResult>()
            : ProtectionPolicyEvaluator.GetEffectiveBlockingFailures(report, ignoreWebRtc);

        var canRecoverNow = blocked && report is not null && !report.Network.ProxyPathSkipped && effectiveFailures.Count == 0;
        var tripReason = effectiveFailures.Count > 0
            ? ProtectionPolicyEvaluator.FormatTripReason(effectiveFailures)
            : blocked
                ? string.IsNullOrWhiteSpace(existingTripReason) || existingTripReason == "暂无"
                    ? "当前仍处于阻断锁定中，点击「检查并解除阻断」确认恢复"
                    : existingTripReason
                : "暂无";

        var exitSummary = FormatExitPathSummary(report?.Network);
        return new MainWindowUiDecision(
            badge,
            launchGate.Allowed,
            launchGate.Reason,
            canRecoverNow,
            tripReason,
            exitSummary);
    }

    public static string FormatExitPathSummary(NetworkSnapshot? network)
    {
        if (network is null)
        {
            return "—";
        }

        var primary = string.IsNullOrWhiteSpace(network.ExitIp)
            ? "IPv4 未取得"
            : $"{network.ExitIp}（{network.ExitCountry}）";

        if (!network.SystemProxyConfigured)
        {
            return primary;
        }

        var tunPart = string.IsNullOrWhiteSpace(network.TunDirectExitIp)
            ? "TUN 直连未取得"
            : $"TUN {network.TunDirectExitIp}（{network.TunDirectExitCountry}）";
        return $"代理 {primary} | {tunPart}";
    }

    public static string FormatCheckEvidence(CheckResult? check)
    {
        if (check is null)
        {
            return "点击左侧检查矩阵任意一行，查看完整详情与结构化 Evidence。";
        }

        var lines = new List<string>
        {
            $"检查项：{check.Title} ({check.Id})",
            $"状态：{check.StatusLabel}（{(check.Blocking ? "阻断项" : "非阻断项")}）",
            $"详情：{check.Detail}"
        };

        if (check.Evidence is { Count: > 0 })
        {
            lines.Add("结构化 Evidence：");
            foreach (var kv in check.Evidence.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
            {
                var value = string.IsNullOrWhiteSpace(kv.Value) ? "(空)" : kv.Value;
                lines.Add($"  {kv.Key} = {value}");
            }
        }
        else
        {
            lines.Add("结构化 Evidence：无");
        }

        return string.Join(Environment.NewLine, lines);
    }
}
