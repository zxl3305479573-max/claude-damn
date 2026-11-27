using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClaudeDesktopGuardian.Core;

public sealed class GuardianConfigStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    private readonly string _path;

    public GuardianConfigStore(string? path = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ClaudeDesktopGuardian",
            "config.json");
    }

    public string ConfigPath => _path;

    public GuardianConfig Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return new GuardianConfig();
            }

            var raw = File.ReadAllText(_path, Encoding.UTF8);
            if (raw.Length > 65536)
            {
                return new GuardianConfig();
            }

            var loaded = JsonSerializer.Deserialize<GuardianConfig>(raw, JsonOptions);
            return loaded is null ? new GuardianConfig() : SanitizeAndValidate(loaded, throwOnError: false);
        }
        catch
        {
            return new GuardianConfig();
        }
    }

    public GuardianConfig Save(GuardianConfig config, bool preserveExistingApiKeyIfEmpty = false)
    {
        var validated = SanitizeAndValidate(config, throwOnError: true);

        if (preserveExistingApiKeyIfEmpty && validated.IpReputation is not null &&
            string.IsNullOrEmpty(validated.IpReputation.Key))
        {
            var existing = Load();
            if (existing.IpReputation is not null &&
                string.Equals(existing.IpReputation.Url, validated.IpReputation.Url, StringComparison.Ordinal))
            {
                validated = validated with
                {
                    IpReputation = validated.IpReputation with { Key = existing.IpReputation.Key }
                };
            }
        }

        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temp = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temp, JsonSerializer.Serialize(validated, JsonOptions), new UTF8Encoding(false));
            File.Move(temp, _path, true);
        }
        finally
        {
            if (File.Exists(temp))
            {
                try { File.Delete(temp); } catch { }
            }
        }

        return validated;
    }

    public static GuardianConfig SanitizeAndValidate(GuardianConfig input, bool throwOnError)
    {
        var proxyMode = ProxyClientModes.Normalize(input.ProxyClientMode);
        if (throwOnError && !string.IsNullOrWhiteSpace(input.ProxyClientMode) &&
            !ProxyClientModes.IsValid(input.ProxyClientMode))
        {
            throw new ArgumentException($"不支持的代理客户端模式：{input.ProxyClientMode}");
        }

        var expectedCountry = string.IsNullOrWhiteSpace(input.ExpectedExitCountry)
            ? null
            : input.ExpectedExitCountry.Trim().ToUpperInvariant();
        if (expectedCountry is not null && !Regex.IsMatch(expectedCountry, "^[A-Z]{2}$"))
        {
            if (throwOnError)
            {
                throw new ArgumentException("期望出口国家必须是两位 ISO 国家代码（例如 US、JP、SG）");
            }

            expectedCountry = null;
        }

        var expectedIp = string.IsNullOrWhiteSpace(input.ExpectedExitIp)
            ? null
            : input.ExpectedExitIp.Trim();
        if (expectedIp is not null && !IPAddress.TryParse(expectedIp, out _))
        {
            if (throwOnError)
            {
                throw new ArgumentException("期望出口 IP 格式无效");
            }

            expectedIp = null;
        }

        var expectedLocale = string.IsNullOrWhiteSpace(input.ExpectedLocale)
            ? null
            : input.ExpectedLocale.Trim();
        if (expectedLocale is not null && !Regex.IsMatch(expectedLocale, "^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$"))
        {
            if (throwOnError)
            {
                throw new ArgumentException("期望地区 Locale 格式无效（例如 en-US、ja-JP）");
            }

            expectedLocale = null;
        }

        var flClash = string.IsNullOrWhiteSpace(input.FlClashController)
            ? null
            : input.FlClashController.Trim();
        if (flClash is not null && !flClash.Equals("auto", StringComparison.OrdinalIgnoreCase))
        {
            var endpoint = ClashEndpointValidator.NormalizeLoopbackEndpoint(flClash);
            if (endpoint is null)
            {
                if (throwOnError)
                {
                    throw new ArgumentException("FlClash 控制端口只接受本机地址，例如 9090 或 127.0.0.1:9090");
                }

                flClash = null;
            }
            else
            {
                flClash = endpoint;
            }
        }
        else
        {
            flClash = null;
        }

        var proxyGroup = string.IsNullOrWhiteSpace(input.ClashProxyGroup)
            ? "GLOBAL"
            : input.ClashProxyGroup.Trim();
        if (proxyGroup.IndexOfAny(new[] { ',', '\r', '\n' }) >= 0)
        {
            if (throwOnError)
            {
                throw new ArgumentException("Clash 代理组名不能包含逗号或换行");
            }

            proxyGroup = "GLOBAL";
        }

        var webrtcPolicy = WebRtcPolicies.Normalize(input.WebRtcPolicy);
        if (throwOnError && !string.IsNullOrWhiteSpace(input.WebRtcPolicy) &&
            !WebRtcPolicies.IsValid(input.WebRtcPolicy))
        {
            throw new ArgumentException($"不支持的 WebRTC 策略：{input.WebRtcPolicy}（仅支持 proxy 或 reject）");
        }

        var lightSeconds = Math.Clamp(input.LightIntervalSeconds, 2, 60);
        var fullMinutes = Math.Clamp(input.FullIntervalMinutes, 1, 180);

        var disabled = (input.DisabledOptionalChecks ?? Array.Empty<string>())
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Select(id => id.Trim())
            .Where(GuardianCheckIds.IsOptional)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        IpReputationConfig? ipRep = null;
        if (input.IpReputation is not null && !string.IsNullOrWhiteSpace(input.IpReputation.Url))
        {
            var url = input.IpReputation.Url.Trim();
            var probeUrl = Regex.Replace(url, @"\{\{?ip\}?\}", "198.51.100.1", RegexOptions.IgnoreCase);
            var validUrl = Uri.TryCreate(probeUrl, UriKind.Absolute, out var parsed) &&
                           string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
                           !Regex.IsMatch(url, @"[\s\x00-\x1f\x7f]");
            if (!validUrl)
            {
                if (throwOnError)
                {
                    throw new ArgumentException("IP 信誉数据源 URL 必须是合法的 https:// 地址");
                }
            }
            else
            {
                var key = input.IpReputation.Key ?? string.Empty;
                if (Regex.IsMatch(key, @"[\r\n\x00-\x1f\x7f]"))
                {
                    if (throwOnError)
                    {
                        throw new ArgumentException("IP 信誉 API Key 不能包含控制字符或换行");
                    }

                    key = string.Empty;
                }

                var threshold = input.IpReputation.Threshold;
                if (double.IsNaN(threshold) || double.IsInfinity(threshold) || threshold < 0 || threshold > 100)
                {
                    if (throwOnError)
                    {
                        throw new ArgumentException("IP 信誉风险分阈值必须在 0-100 之间");
                    }

                    threshold = 25;
                }

                var cacheDays = input.IpReputation.CacheDays;
                if (cacheDays < 1 || cacheDays > 90)
                {
                    if (throwOnError)
                    {
                        throw new ArgumentException("IP 信誉缓存天数必须在 1-90 之间");
                    }

                    cacheDays = 7;
                }

                ipRep = new IpReputationConfig(url, key, threshold, cacheDays);
            }
        }

        return input with
        {
            ProxyClientMode = proxyMode,
            VpnAdapterPattern = string.IsNullOrWhiteSpace(input.VpnAdapterPattern) ? null : input.VpnAdapterPattern.Trim(),
            ExpectedExitCountry = expectedCountry,
            ExpectedExitIp = expectedIp,
            ExpectedLocale = expectedLocale,
            FlClashController = flClash,
            ClashProxyGroup = proxyGroup,
            LightIntervalSeconds = lightSeconds,
            FullIntervalMinutes = fullMinutes,
            DisabledOptionalChecks = disabled,
            IpReputation = ipRep,
            WebRtcPolicy = webrtcPolicy
        };
    }
}

public static class ClashEndpointValidator
{
    public static string? NormalizeLoopbackEndpoint(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var addr = raw.Trim();
        if (addr.StartsWith("unix://", StringComparison.OrdinalIgnoreCase) ||
            addr.StartsWith('/') ||
            addr.StartsWith('\\') ||
            addr.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (Regex.IsMatch(addr, @"^\d{1,5}$"))
        {
            addr = "127.0.0.1:" + addr;
        }

        addr = Regex.Replace(addr, @"^0\.0\.0\.0:", "127.0.0.1:");
        addr = Regex.Replace(addr, @"^\[::\]:", "127.0.0.1:");
        addr = Regex.Replace(addr, @"^:", "127.0.0.1:");
        if (!addr.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            addr = "http://" + addr;
        }

        if (!Uri.TryCreate(addr, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var host = uri.Host.Trim('[', ']').ToLowerInvariant();
        if (host is not ("127.0.0.1" or "localhost" or "::1"))
        {
            return null;
        }

        if (uri.Port < 1 || uri.Port > 65535)
        {
            return null;
        }

        return $"127.0.0.1:{uri.Port}";
    }
}

public sealed class IpHistoryStore
{
    private const long WindowSeconds = 172800; // 48 hours
    private readonly string _directory;
    private readonly string _historyPath;
    private readonly string _lastIpPath;

    public IpHistoryStore(string? directory = null)
    {
        _directory = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ClaudeDesktopGuardian");
        _historyPath = Path.Combine(_directory, "iphistory.log");
        _lastIpPath = Path.Combine(_directory, "lastip.txt");
    }

    public (string PreviousIp, int UniqueCount48h) RecordAndInspect(string currentIp, DateTimeOffset nowUtc)
    {
        var previousIp = ReadLastIp();
        if (string.IsNullOrWhiteSpace(currentIp) || currentIp.Any(char.IsWhiteSpace))
        {
            return (previousIp, CountUniqueInWindow(nowUtc));
        }

        Directory.CreateDirectory(_directory);
        var nowEpoch = nowUtc.ToUnixTimeSeconds();
        var cutoff = nowEpoch - WindowSeconds;
        var kept = new List<string>();
        var unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (File.Exists(_historyPath))
        {
            foreach (var line in File.ReadAllLines(_historyPath, Encoding.ASCII))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2 && long.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var stamp) && stamp >= cutoff)
                {
                    kept.Add(line);
                    unique.Add(parts[0]);
                }
            }
        }

        kept.Add($"{currentIp} {nowEpoch}");
        unique.Add(currentIp);

        WriteAtomically(_historyPath, string.Join('\n', kept) + "\n", Encoding.ASCII);
        WriteAtomically(_lastIpPath, currentIp, Encoding.ASCII);
        return (previousIp, unique.Count);
    }

    public string ReadLastIp()
    {
        try
        {
            return File.Exists(_lastIpPath) ? File.ReadAllText(_lastIpPath, Encoding.ASCII).Trim() : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private int CountUniqueInWindow(DateTimeOffset nowUtc)
    {
        if (!File.Exists(_historyPath))
        {
            return 0;
        }

        var cutoff = nowUtc.ToUnixTimeSeconds() - WindowSeconds;
        var unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var line in File.ReadAllLines(_historyPath, Encoding.ASCII))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2 && long.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var stamp) && stamp >= cutoff)
                {
                    unique.Add(parts[0]);
                }
            }
        }
        catch
        {
        }

        return unique.Count;
    }

    private static void WriteAtomically(string path, string content, Encoding encoding)
    {
        var tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(tmp, content, encoding);
            File.Move(tmp, path, true);
        }
        finally
        {
            if (File.Exists(tmp))
            {
                try { File.Delete(tmp); } catch { }
            }
        }
    }
}

public sealed class GuardianLogger
{
    private const long MaxLogBytes = 524288; // 512 KiB
    private static readonly Regex SafeLinePattern = new(
        @"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z action=[a-z0-9-]+ status=[a-z0-9-]+ duration_ms=\d+(?: [a-z0-9-]+=(?:ok|warn|fail|unknown|skip))*$",
        RegexOptions.Compiled);

    private readonly string _logPath;
    private readonly object _gate = new();

    public GuardianLogger(string? logPath = null)
    {
        _logPath = logPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ClaudeDesktopGuardian",
            "logs",
            "guardian.log");
    }

    public string LogPath => _logPath;

    public void LogAction(
        string action,
        string status,
        long durationMs,
        IReadOnlyList<CheckResult>? checks = null,
        bool enabled = true)
    {
        if (!enabled)
        {
            return;
        }

        var safeAction = SanitizeToken(action, "unknown");
        var safeStatus = SanitizeToken(status, "unknown");
        var safeDuration = Math.Max(0, durationMs);
        var builder = new StringBuilder();
        builder.Append(DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture));
        builder.Append(" action=").Append(safeAction);
        builder.Append(" status=").Append(safeStatus);
        builder.Append(" duration_ms=").Append(safeDuration);

        if (checks is not null)
        {
            foreach (var check in checks)
            {
                var safeId = SanitizeToken(check.Id, string.Empty);
                if (!string.IsNullOrEmpty(safeId))
                {
                    builder.Append(' ').Append(safeId).Append('=').Append(check.Status.ToString().ToLowerInvariant());
                }
            }
        }

        var line = builder.ToString();
        if (!SafeLinePattern.IsMatch(line))
        {
            return;
        }

        lock (_gate)
        {
            try
            {
                var dir = Path.GetDirectoryName(_logPath);
                if (!string.IsNullOrWhiteSpace(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                var entryBytes = Encoding.UTF8.GetByteCount(line + "\n");
                if (File.Exists(_logPath) && new FileInfo(_logPath).Length + entryBytes > MaxLogBytes)
                {
                    File.Move(_logPath, _logPath + ".1", true);
                }

                File.AppendAllText(_logPath, line + "\n", new UTF8Encoding(false));
            }
            catch
            {
            }
        }
    }

    public IReadOnlyList<string> ReadSanitizedTail(int maxLines = 2000)
    {
        if (!File.Exists(_logPath))
        {
            return Array.Empty<string>();
        }

        try
        {
            return File.ReadAllLines(_logPath, Encoding.UTF8)
                .Where(line => SafeLinePattern.IsMatch(line))
                .TakeLast(maxLines)
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static string SanitizeToken(string value, string fallback)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        var cleaned = Regex.Replace(value.Trim().ToLowerInvariant(), @"[^a-z0-9-]", "-").Trim('-');
        return string.IsNullOrEmpty(cleaned) ? fallback : cleaned.Length > 32 ? cleaned[..32] : cleaned;
    }
}

public static class DiagnosticsExporter
{
    public static void ExportZip(
        string destinationZipPath,
        GuardianConfig config,
        GuardianState state,
        GuardianReport? report,
        GuardianLogger logger)
    {
        if (string.IsNullOrWhiteSpace(destinationZipPath))
        {
            throw new ArgumentException("请指定诊断包导出路径", nameof(destinationZipPath));
        }

        var stageDir = Path.Combine(Path.GetTempPath(), "cdg-diag-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stageDir);
        try
        {
            var jsonOptions = new JsonSerializerOptions { WriteIndented = true };

            var envPayload = new
            {
                schema_version = 2,
                app = "ClaudeDesktopGuardian",
                platform = "Windows",
                os_version = Environment.OSVersion.VersionString,
                dotnet_version = Environment.Version.ToString(),
                generated_at = DateTimeOffset.UtcNow.ToString("o")
            };
            File.WriteAllText(
                Path.Combine(stageDir, "environment.json"),
                JsonSerializer.Serialize(envPayload, jsonOptions),
                new UTF8Encoding(false));

            var checkStatuses = report?.Checks.ToDictionary(
                check => check.Id,
                check => check.Status.ToString().ToLowerInvariant(),
                StringComparer.OrdinalIgnoreCase) ?? new Dictionary<string, string>();
            var recentPayload = new
            {
                observed_at = report?.ObservedAt.ToString("o"),
                blocked = state.Blocked,
                timezone_override_active = state.TimezoneOverrideActive,
                wfp_policy_state = report?.Network.WfpPolicyState ?? "unknown",
                proxy_client_mode = config.ProxyClientMode,
                checks = checkStatuses
            };
            File.WriteAllText(
                Path.Combine(stageDir, "recent-status.json"),
                JsonSerializer.Serialize(recentPayload, jsonOptions),
                new UTF8Encoding(false));

            // Redact API key & expected IP from exported config
            var redactedConfig = new
            {
                proxy_client_mode = config.ProxyClientMode,
                expected_exit_country = config.ExpectedExitCountry,
                expected_exit_ip_configured = !string.IsNullOrWhiteSpace(config.ExpectedExitIp),
                expected_locale = config.ExpectedLocale,
                wfp_strict_enabled = config.WfpStrictEnabled,
                wfp_allow_loopback = config.WfpAllowLoopback,
                tcp_only_enabled = config.TcpOnlyEnabled,
                webrtc_policy = WebRtcPolicies.Normalize(config.WebRtcPolicy),
                allow_optional_failures = config.AllowOptionalFailures,
                logging_enabled = config.LoggingEnabled,
                disabled_optional_checks = config.DisabledOptionalChecks ?? Array.Empty<string>(),
                ip_reputation = config.IpReputation is null
                    ? null
                    : new
                    {
                        url_host = ExtractSafeHost(config.IpReputation.Url),
                        key_configured = !string.IsNullOrEmpty(config.IpReputation.Key),
                        threshold = config.IpReputation.Threshold,
                        cache_days = config.IpReputation.CacheDays
                    }
            };
            File.WriteAllText(
                Path.Combine(stageDir, "config-redacted.json"),
                JsonSerializer.Serialize(redactedConfig, jsonOptions),
                new UTF8Encoding(false));

            var logs = logger.ReadSanitizedTail(2000);
            File.WriteAllText(
                Path.Combine(stageDir, "guardian.log"),
                string.Join("\n", logs) + "\n",
                new UTF8Encoding(false));

            if (File.Exists(destinationZipPath))
            {
                File.Delete(destinationZipPath);
            }

            ZipFile.CreateFromDirectory(stageDir, destinationZipPath, CompressionLevel.Optimal, includeBaseDirectory: false);
        }
        finally
        {
            try { Directory.Delete(stageDir, recursive: true); } catch { }
        }
    }

    private static string ExtractSafeHost(string? templateUrl)
    {
        if (string.IsNullOrWhiteSpace(templateUrl))
        {
            return string.Empty;
        }

        var normalized = Regex.Replace(templateUrl.Trim(), @"\{\{?ip\}?\}", "198.51.100.1", RegexOptions.IgnoreCase);
        return Uri.TryCreate(normalized, UriKind.Absolute, out var uri) ? uri.Host : string.Empty;
    }
}
