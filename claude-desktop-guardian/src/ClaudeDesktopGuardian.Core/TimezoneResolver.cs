using System.Net.Http;

namespace ClaudeDesktopGuardian.Core;

public sealed record TimezoneResolution(
    string IanaId,
    string WindowsId,
    string Source);

public static class WindowsTimezoneMapper
{
    private static readonly IReadOnlyDictionary<string, string> FallbackMappings =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["America/Los_Angeles"] = "Pacific Standard Time",
            ["America/Denver"] = "Mountain Standard Time",
            ["America/Chicago"] = "Central Standard Time",
            ["America/New_York"] = "Eastern Standard Time",
            ["America/Toronto"] = "Eastern Standard Time",
            ["America/Vancouver"] = "Pacific Standard Time",
            ["America/Sao_Paulo"] = "E. South America Standard Time",
            ["Europe/London"] = "GMT Standard Time",
            ["Europe/Paris"] = "Romance Standard Time",
            ["Europe/Berlin"] = "W. Europe Standard Time",
            ["Europe/Moscow"] = "Russian Standard Time",
            ["Asia/Tokyo"] = "Tokyo Standard Time",
            ["Asia/Seoul"] = "Korea Standard Time",
            ["Asia/Shanghai"] = "China Standard Time",
            ["Asia/Taipei"] = "Taipei Standard Time",
            ["Asia/Hong_Kong"] = "China Standard Time",
            ["Asia/Singapore"] = "Singapore Standard Time",
            ["Asia/Kolkata"] = "India Standard Time",
            ["Australia/Sydney"] = "AUS Eastern Standard Time",
            ["Pacific/Auckland"] = "New Zealand Standard Time"
        };

    public static bool TryMap(string? ianaId, out string windowsId)
    {
        windowsId = string.Empty;
        if (string.IsNullOrWhiteSpace(ianaId))
        {
            return false;
        }

        if (TimeZoneInfo.TryConvertIanaIdToWindowsId(ianaId.Trim(), out var converted) &&
            !string.IsNullOrWhiteSpace(converted))
        {
            windowsId = converted;
            return true;
        }

        if (FallbackMappings.TryGetValue(ianaId.Trim(), out var fallback))
        {
            windowsId = fallback;
            return true;
        }

        return false;
    }

    public static bool IsKnownWindowsId(string? windowsId)
    {
        if (string.IsNullOrWhiteSpace(windowsId))
        {
            return false;
        }

        return TimeZoneInfo.GetSystemTimeZones()
            .Any(zone => string.Equals(zone.Id, windowsId, StringComparison.OrdinalIgnoreCase));
    }
}

public sealed class ExitTimezoneResolver
{
    private readonly HttpClient _httpClient;

    public ExitTimezoneResolver(HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(8)
        };
    }

    public async Task<TimezoneResolution?> ResolveAsync(CancellationToken cancellationToken)
    {
        var sources = new[]
        {
            ("ipapi.co", "https://ipapi.co/timezone/"),
            ("ipinfo.io", "https://ipinfo.io/timezone")
        };

        foreach (var (source, uri) in sources)
        {
            try
            {
                using var response = await _httpClient.GetAsync(uri, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                var ianaId = (await response.Content.ReadAsStringAsync(cancellationToken)).Trim();
                if (WindowsTimezoneMapper.TryMap(ianaId, out var windowsId))
                {
                    return new TimezoneResolution(ianaId, windowsId, source);
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
            }
            catch
            {
            }
        }

        return null;
    }
}
