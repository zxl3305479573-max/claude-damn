using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace ClaudeDesktopGuardian.Core;

public sealed record TimezoneResolution(
    string IanaId,
    string WindowsId,
    string Source);

public static class CountryDefaults
{
    private static readonly IReadOnlyDictionary<string, string> CountryTimezones =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["US"] = "America/New_York",
            ["JP"] = "Asia/Tokyo",
            ["TW"] = "Asia/Taipei",
            ["HK"] = "Asia/Hong_Kong",
            ["SG"] = "Asia/Singapore",
            ["GB"] = "Europe/London",
            ["DE"] = "Europe/Berlin",
            ["FR"] = "Europe/Paris",
            ["KR"] = "Asia/Seoul",
            ["AU"] = "Australia/Sydney",
            ["CA"] = "America/Toronto",
            ["MY"] = "Asia/Kuala_Lumpur"
        };

    private static readonly IReadOnlyDictionary<string, string> CountryLocales =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["US"] = "en-US",
            ["JP"] = "ja-JP",
            ["TW"] = "zh-TW",
            ["HK"] = "zh-HK",
            ["SG"] = "en-SG",
            ["GB"] = "en-GB",
            ["DE"] = "de-DE",
            ["FR"] = "fr-FR",
            ["KR"] = "ko-KR",
            ["AU"] = "en-AU",
            ["CA"] = "en-CA",
            ["MY"] = "ms-MY"
        };

    public static string? GetDefaultIanaTimezone(string? countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode))
        {
            return null;
        }

        return CountryTimezones.TryGetValue(countryCode.Trim(), out var tz) ? tz : null;
    }

    public static string GetExpectedLocale(string? countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode))
        {
            return "en-US";
        }

        return CountryLocales.TryGetValue(countryCode.Trim(), out var locale) ? locale : "en-US";
    }
}

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
            ["Asia/Kuala_Lumpur"] = "Singapore Standard Time",
            ["Asia/Kolkata"] = "India Standard Time",
            ["Australia/Sydney"] = "AUS Eastern Standard Time",
            ["Australia/Melbourne"] = "AUS Eastern Standard Time",
            ["Pacific/Auckland"] = "New Zealand Standard Time"
        };

    [DllImport("icu.dll", CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl)]
    private static extern int ucal_getWindowsTimeZoneID(
        string iana,
        int length,
        StringBuilder windowsId,
        int capacity,
        ref int error);

    public static bool TryMap(string? ianaId, out string windowsId)
    {
        windowsId = string.Empty;
        if (string.IsNullOrWhiteSpace(ianaId))
        {
            return false;
        }

        var trimmed = ianaId.Trim();
        if (TimeZoneInfo.TryConvertIanaIdToWindowsId(trimmed, out var converted) &&
            !string.IsNullOrWhiteSpace(converted))
        {
            windowsId = converted;
            return true;
        }

        if (FallbackMappings.TryGetValue(trimmed, out var fallback))
        {
            windowsId = fallback;
            return true;
        }

        if (OperatingSystem.IsWindows())
        {
            try
            {
                var buffer = new StringBuilder(128);
                var error = 0;
                var len = ucal_getWindowsTimeZoneID(trimmed, trimmed.Length, buffer, buffer.Capacity, ref error);
                if (error <= 0 && len > 0 && len < buffer.Capacity)
                {
                    windowsId = buffer.ToString();
                    return true;
                }
            }
            catch
            {
            }
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

    public async Task<TimezoneResolution?> ResolveAsync(
        CancellationToken cancellationToken,
        string? fallbackCountryCode = null)
    {
        var textSources = new[]
        {
            ("ipapi.co", "https://ipapi.co/timezone/"),
            ("ipinfo.io", "https://ipinfo.io/timezone")
        };

        foreach (var (source, uri) in textSources)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.UserAgent.ParseAdd("ClaudeDesktopGuardian/2.0");
                using var response = await _httpClient.SendAsync(request, cancellationToken);
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

        // JSON fallback: ifconfig.co / ipwho.is
        var jsonSources = new[]
        {
            ("ifconfig.co", "https://ifconfig.co/json", "time_zone"),
            ("ipwho.is", "https://ipwho.is/", "timezone")
        };
        foreach (var (source, uri, field) in jsonSources)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.UserAgent.ParseAdd("ClaudeDesktopGuardian/2.0");
                using var response = await _httpClient.SendAsync(request, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }

                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                using var doc = JsonDocument.Parse(body);
                string? ianaId = null;
                if (doc.RootElement.TryGetProperty(field, out var prop))
                {
                    if (prop.ValueKind == JsonValueKind.String)
                    {
                        ianaId = prop.GetString();
                    }
                    else if (prop.ValueKind == JsonValueKind.Object &&
                             prop.TryGetProperty("id", out var idProp))
                    {
                        ianaId = idProp.GetString();
                    }
                }

                if (WindowsTimezoneMapper.TryMap(ianaId, out var windowsId))
                {
                    return new TimezoneResolution(ianaId!.Trim(), windowsId, source);
                }
            }
            catch
            {
            }
        }

        // Final fallback by exit country default if provided
        var countryDefault = CountryDefaults.GetDefaultIanaTimezone(fallbackCountryCode);
        if (countryDefault is not null && WindowsTimezoneMapper.TryMap(countryDefault, out var defaultWin))
        {
            return new TimezoneResolution(countryDefault, defaultWin, "country-default");
        }

        return null;
    }
}
