namespace ClaudeDesktopGuardian.Core;

public static class EvidenceFreshness
{
    public static bool EgressBaselineChanged(string previousIp, string previousCountry, string ip, string country) =>
        !string.IsNullOrWhiteSpace(previousIp) && (previousIp != ip || previousCountry != country);

    public static bool NeedsEgressRefresh(DateTimeOffset now, CollectionObservation? observation, string exitIp) =>
        string.IsNullOrWhiteSpace(exitIp) || observation is null || !observation.Succeeded ||
        now < observation.ObservedAt || now - observation.ObservedAt >= TimeSpan.FromSeconds(60);

    public static GuardianReport AfterTimeout(GuardianReport previous, long durationMs) => AfterFailedCheck(previous, durationMs, true);

    public static GuardianReport AfterFailedCheck(GuardianReport previous, long durationMs, bool timedOut) => previous with
    {
        Checks = previous.Checks.Select(check => check.Status == CheckStatus.Skip ? check : check with
        {
            Status = check.Status == CheckStatus.Fail ? CheckStatus.Fail : CheckStatus.Unknown,
            Detail = (timedOut ? "本轮检查超时" : "本轮采集失败") + "，以下为旧证据，等待重新验证；" + check.Detail,
            IsCached = true,
            Evidence = new Dictionary<string, string>(check.Evidence)
            {
                ["cached"] = "true", ["stale"] = "true", ["collection_state"] = timedOut ? "timeout" : "failed"
            }
        }).ToArray(),
        Network = previous.Network with { LastCycleDurationMs = durationMs, LastCycleTimedOut = timedOut }
    };
}
