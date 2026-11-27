namespace ClaudeDesktopGuardian.Core;

public static class EvidenceFreshness
{
    private const string TimeoutPrefix = "本轮检查超时，以下为旧证据，等待重新验证；";
    private const string FailedPrefix = "本轮采集失败，以下为旧证据，等待重新验证；";

    public static bool EgressBaselineChanged(string previousIp, string previousCountry, string ip, string country) =>
        !string.IsNullOrWhiteSpace(previousIp) &&
        !string.IsNullOrWhiteSpace(ip) &&
        (previousIp != ip || previousCountry != country);

    public static bool NeedsEgressRefresh(DateTimeOffset now, CollectionObservation? observation, string exitIp) =>
        string.IsNullOrWhiteSpace(exitIp) || observation is null || !observation.Succeeded ||
        now < observation.ObservedAt || now - observation.ObservedAt >= TimeSpan.FromSeconds(60);

    public static GuardianReport AfterTimeout(GuardianReport previous, long durationMs) => AfterFailedCheck(previous, durationMs, true);

    public static GuardianReport AfterFailedCheck(GuardianReport previous, long durationMs, bool timedOut) => previous with
    {
        Checks = previous.Checks.Select(check => MarkStale(check, timedOut)).ToArray(),
        Network = previous.Network with { LastCycleDurationMs = durationMs, LastCycleTimedOut = timedOut }
    };

    public static GuardianReport AfterSingleCheckFailure(
        GuardianReport previous,
        string checkId,
        long durationMs,
        bool timedOut) => previous with
    {
        Checks = previous.Checks.Select(check =>
            string.Equals(check.Id, checkId, StringComparison.OrdinalIgnoreCase)
                ? MarkStale(check, timedOut)
                : check).ToArray(),
        Network = previous.Network with { LastCycleDurationMs = durationMs, LastCycleTimedOut = timedOut }
    };

    private static CheckResult MarkStale(CheckResult check, bool timedOut)
    {
        if (check.Status == CheckStatus.Skip) return check;
        var prefix = timedOut ? TimeoutPrefix : FailedPrefix;
        return check with
        {
            Status = check.Status == CheckStatus.Fail ? CheckStatus.Fail : CheckStatus.Unknown,
            Detail = prefix + StripStalePrefix(check.Detail),
            IsCached = true,
            Evidence = new Dictionary<string, string>(check.Evidence)
            {
                ["cached"] = "true", ["stale"] = "true", ["collection_state"] = timedOut ? "timeout" : "failed"
            }
        };
    }

    private static string StripStalePrefix(string detail)
    {
        var current = detail;
        while (current.StartsWith(TimeoutPrefix, StringComparison.Ordinal) ||
               current.StartsWith(FailedPrefix, StringComparison.Ordinal))
        {
            current = current.StartsWith(TimeoutPrefix, StringComparison.Ordinal)
                ? current[TimeoutPrefix.Length..]
                : current[FailedPrefix.Length..];
        }

        return current;
    }
}
