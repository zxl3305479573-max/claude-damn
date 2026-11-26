using System.Globalization;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClaudeDesktopGuardian.Core;

public sealed class IpReputationService
{
    public const int DefaultMaxCacheBytes = 262144;
    private readonly HttpClient _httpClient;
    private readonly string _cachePath;
    private readonly int _maxCacheBytes;

    public IpReputationService(
        HttpClient httpClient,
        string? cachePath = null,
        int maxCacheBytes = DefaultMaxCacheBytes)
    {
        _httpClient = httpClient;
        _cachePath = cachePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ClaudeDesktopGuardian",
            "ip-reputation.json");
        _maxCacheBytes = Math.Max(256, maxCacheBytes);
    }

    public async Task<(IpReputationRecord? Record, string Error)> LookupAsync(
        string exitIp,
        IpReputationConfig config,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(exitIp))
        {
            return (null, "未取得出口 IP，无法查询信誉");
        }

        if (string.IsNullOrWhiteSpace(config.Url) ||
            !config.Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return (null, "未配置合法的 HTTPS 信誉数据源");
        }

        var cacheKey = $"{config.Url}|{exitIp}";
        var cache = ReadCache();
        cache.TryGetValue(cacheKey, out var cached);
        if (cached is not null)
        {
            var ttlDays = Math.Clamp(config.CacheDays, 1, 90);
            if ((nowUtc - cached.CheckedAt).TotalDays < ttlDays)
            {
                return (cached, string.Empty);
            }
        }

        var fetched = await FetchFromProviderAsync(exitIp, config, nowUtc, cancellationToken);
        if (fetched is null)
        {
            if (cached is not null)
            {
                return (null, "信誉缓存已过期且本次数据源刷新失败");
            }

            return (null, "信誉数据源探测失败或未返回可用数据");
        }

        cache[cacheKey] = fetched;
        WriteCache(cache);
        return (fetched, string.Empty);
    }

    public static string? BuildRequestUrl(string templateUrl, string exitIp)
    {
        if (string.IsNullOrWhiteSpace(templateUrl) || string.IsNullOrWhiteSpace(exitIp))
        {
            return null;
        }

        var trimmed = templateUrl.Trim();
        if (!Uri.TryCreate(trimmed.Replace("{ip}", "198.51.100.1", StringComparison.OrdinalIgnoreCase), UriKind.Absolute, out var originalUri) ||
            !string.Equals(originalUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var escapedIp = Uri.EscapeDataString(exitIp.Trim());
        string fullUrl;
        if (trimmed.Contains("{ip}", StringComparison.OrdinalIgnoreCase))
        {
            fullUrl = Regex.Replace(trimmed, @"\{\{?ip\}?\}", escapedIp, RegexOptions.IgnoreCase);
        }
        else
        {
            var separator = trimmed.Contains('?', StringComparison.Ordinal) ? "&" : "?";
            fullUrl = $"{trimmed}{separator}ip={escapedIp}";
        }

        if (!Uri.TryCreate(fullUrl, UriKind.Absolute, out var finalUri) ||
            !string.Equals(finalUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(finalUri.Host, originalUri.Host, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return fullUrl;
    }

    private async Task<IpReputationRecord?> FetchFromProviderAsync(
        string exitIp,
        IpReputationConfig config,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken)
    {
        try
        {
            var fullUrl = BuildRequestUrl(config.Url, exitIp);
            if (string.IsNullOrEmpty(fullUrl))
            {
                return null;
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, fullUrl);
            request.Headers.UserAgent.ParseAdd("ClaudeDesktopGuardian/2.0");
            if (!string.IsNullOrWhiteSpace(config.Key))
            {
                request.Headers.TryAddWithoutValidation("X-API-Key", config.Key);
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(12));
            using var response = await _httpClient.SendAsync(request, timeout.Token);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var body = await response.Content.ReadAsStringAsync(timeout.Token);
            if (string.IsNullOrWhiteSpace(body))
            {
                return null;
            }

            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            return NormalizePayload(doc.RootElement, nowUtc);
        }
        catch
        {
            return null;
        }
    }

    public static IpReputationRecord NormalizePayload(JsonElement root, DateTimeOffset nowUtc)
    {
        var flat = new List<(string Name, JsonElement Value)>();
        FlattenObject(root, flat, maxDepth: 3);

        var score = FindNumber(flat, "fraud_score", "fraudscore", "risk_score", "riskscore", "score", "threat_score", "threatscore");
        var level = FindText(flat, "risk_level", "risklevel", "level", "verdict", "ai_verdict");
        var isProxy = FindBool(flat, "is_proxy", "proxy", "is_residential_proxy", "residential_proxy", "residential_proxy_access");
        var isVpn = FindBool(flat, "is_vpn", "vpn", "is_anonymous_vpn", "anonymous_vpn", "privacy");
        var isTor = FindBool(flat, "is_tor", "tor", "is_tor_exit", "tor_exit");
        var isHosting = FindBool(flat, "is_datacenter", "datacenter", "is_hosting", "hosting", "is_cloud", "cloud", "is_server", "server");
        var blacklist = FindNumber(flat, "blacklist", "blacklists", "blacklist_count", "dnsbl", "abuse_score", "abuse_confidence_score");

        return new IpReputationRecord(nowUtc, score, level, isProxy, isVpn, isTor, isHosting, blacklist);
    }

    private static void FlattenObject(JsonElement element, List<(string Name, JsonElement Value)> output, int maxDepth)
    {
        if (element.ValueKind != JsonValueKind.Object || maxDepth <= 0)
        {
            return;
        }

        foreach (var prop in element.EnumerateObject())
        {
            if (prop.Value.ValueKind == JsonValueKind.Object)
            {
                FlattenObject(prop.Value, output, maxDepth - 1);
            }
            else
            {
                output.Add((prop.Name, prop.Value));
            }
        }
    }

    private static double? FindNumber(IReadOnlyList<(string Name, JsonElement Value)> props, params string[] names)
    {
        foreach (var exact in new[] { true, false })
        {
            foreach (var target in names)
            {
                foreach (var (name, value) in props)
                {
                    var matched = exact
                        ? string.Equals(name, target, StringComparison.OrdinalIgnoreCase)
                        : name.EndsWith(target, StringComparison.OrdinalIgnoreCase);
                    if (!matched)
                    {
                        continue;
                    }

                    if (value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out var number) &&
                        !double.IsNaN(number) && !double.IsInfinity(number))
                    {
                        return number;
                    }

                    if (value.ValueKind == JsonValueKind.String &&
                        double.TryParse(value.GetString()?.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed) &&
                        !double.IsNaN(parsed) && !double.IsInfinity(parsed))
                    {
                        return parsed;
                    }
                }
            }
        }

        return null;
    }

    private static string? FindText(IReadOnlyList<(string Name, JsonElement Value)> props, params string[] names)
    {
        foreach (var exact in new[] { true, false })
        {
            foreach (var target in names)
            {
                foreach (var (name, value) in props)
                {
                    var matched = exact
                        ? string.Equals(name, target, StringComparison.OrdinalIgnoreCase)
                        : name.EndsWith(target, StringComparison.OrdinalIgnoreCase);
                    if (!matched || value.ValueKind != JsonValueKind.String)
                    {
                        continue;
                    }

                    var text = Regex.Replace(value.GetString() ?? string.Empty, @"[\r\n\x00-\x1f\x7f]", " ").Trim();
                    if (text.Length > 40)
                    {
                        text = text[..40];
                    }

                    if (!string.IsNullOrEmpty(text))
                    {
                        return text;
                    }
                }
            }
        }

        return null;
    }

    private static bool? FindBool(IReadOnlyList<(string Name, JsonElement Value)> props, params string[] names)
    {
        foreach (var exact in new[] { true, false })
        {
            foreach (var target in names)
            {
                foreach (var (name, value) in props)
                {
                    var matched = exact
                        ? string.Equals(name, target, StringComparison.OrdinalIgnoreCase)
                        : name.EndsWith(target, StringComparison.OrdinalIgnoreCase);
                    if (!matched)
                    {
                        continue;
                    }

                    if (value.ValueKind is JsonValueKind.True or JsonValueKind.False)
                    {
                        return value.GetBoolean();
                    }

                    if (value.ValueKind == JsonValueKind.String)
                    {
                        var normalized = value.GetString()?.Trim().ToLowerInvariant();
                        if (normalized is "true" or "yes" or "1") return true;
                        if (normalized is "false" or "no" or "0") return false;
                    }
                }
            }
        }

        return null;
    }

    private Dictionary<string, IpReputationRecord> ReadCache()
    {
        try
        {
            if (!File.Exists(_cachePath))
            {
                return new Dictionary<string, IpReputationRecord>(StringComparer.Ordinal);
            }

            var raw = File.ReadAllText(_cachePath, Encoding.UTF8);
            if (raw.Length > _maxCacheBytes)
            {
                return new Dictionary<string, IpReputationRecord>(StringComparer.Ordinal);
            }

            return JsonSerializer.Deserialize<Dictionary<string, IpReputationRecord>>(raw)
                   ?? new Dictionary<string, IpReputationRecord>(StringComparer.Ordinal);
        }
        catch
        {
            return new Dictionary<string, IpReputationRecord>(StringComparer.Ordinal);
        }
    }

    private void WriteCache(Dictionary<string, IpReputationRecord> cache)
    {
        try
        {
            // LRU eviction by CheckedAt when cache exceeds byte budget so updates never stall permanently
            var json = JsonSerializer.Serialize(cache);
            while (Encoding.UTF8.GetByteCount(json) > _maxCacheBytes && cache.Count > 1)
            {
                var oldestKey = cache
                    .OrderBy(kv => kv.Value.CheckedAt)
                    .Select(kv => kv.Key)
                    .First();
                cache.Remove(oldestKey);
                json = JsonSerializer.Serialize(cache);
            }

            if (Encoding.UTF8.GetByteCount(json) > _maxCacheBytes)
            {
                return;
            }

            var dir = Path.GetDirectoryName(_cachePath);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var tmp = _cachePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            File.WriteAllText(tmp, json, new UTF8Encoding(false));
            File.Move(tmp, _cachePath, true);
        }
        catch
        {
        }
    }
}
