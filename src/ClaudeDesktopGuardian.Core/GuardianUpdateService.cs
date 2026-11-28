using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClaudeDesktopGuardian.Core;

public sealed record GuardianUpdate(
    string Version,
    string PackageName,
    Uri PackageUri,
    Uri ChecksumsUri,
    Uri ReleaseUri);

public sealed class GuardianUpdateService
{
    private const string Repository = "snowpear-lab/claude-damn";
    private const long MaximumPackageBytes = 512L * 1024 * 1024;
    private static readonly HashSet<string> DownloadHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com"
    };
    private static readonly Regex TagPattern = new(
        "^guardian-v(?<version>\\d+\\.\\d+\\.\\d+)$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private readonly HttpClient _httpClient;

    public GuardianUpdateService(HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("ClaudeDesktopGuardian");
    }

    public async Task<GuardianUpdate?> CheckAsync(string currentVersion, CancellationToken cancellationToken = default)
    {
        if (!Version.TryParse(currentVersion, out var installedVersion))
        {
            throw new InvalidOperationException("当前程序版本号无效");
        }

        using var response = await _httpClient.GetAsync(
            $"https://api.github.com/repos/{Repository}/releases?per_page=100",
            cancellationToken);
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync(cancellationToken);
        return SelectUpdate(json, installedVersion);
    }

    public async Task<string> DownloadAndVerifyAsync(
        GuardianUpdate update,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        ValidateGitHubUri(update.PackageUri);
        ValidateGitHubUri(update.ChecksumsUri);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(destinationPath))!);

        var expectedHash = await DownloadChecksumAsync(update, cancellationToken);
        try
        {
            using var response = await GetReleaseAssetAsync(update.PackageUri, cancellationToken);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength > MaximumPackageBytes)
            {
                throw new InvalidDataException("更新包超过允许大小");
            }

            await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
            await using var output = new FileStream(
                destinationPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                65536,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[65536];
            long total = 0;
            while (true)
            {
                var count = await input.ReadAsync(buffer, cancellationToken);
                if (count == 0)
                {
                    break;
                }

                total += count;
                if (total > MaximumPackageBytes)
                {
                    throw new InvalidDataException("更新包超过允许大小");
                }

                hash.AppendData(buffer, 0, count);
                await output.WriteAsync(buffer.AsMemory(0, count), cancellationToken);
            }

            await output.FlushAsync(cancellationToken);
            var actualHash = Convert.ToHexString(hash.GetHashAndReset());
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(expectedHash),
                    Convert.FromHexString(actualHash)))
            {
                throw new InvalidDataException("更新包 SHA-256 校验失败");
            }

            return actualHash;
        }
        catch
        {
            if (File.Exists(destinationPath))
            {
                File.Delete(destinationPath);
            }

            throw;
        }
    }

    public static GuardianUpdate? SelectUpdate(string releasesJson, Version installedVersion)
    {
        using var document = JsonDocument.Parse(releasesJson);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("GitHub Release 响应格式无效");
        }

        GuardianUpdate? selected = null;
        Version? selectedVersion = null;
        foreach (var release in document.RootElement.EnumerateArray())
        {
            if (release.TryGetProperty("draft", out var draft) && draft.GetBoolean() ||
                release.TryGetProperty("prerelease", out var prerelease) && prerelease.GetBoolean() ||
                !TryGetString(release, "tag_name", out var tag))
            {
                continue;
            }

            var match = TagPattern.Match(tag);
            if (!match.Success || !Version.TryParse(match.Groups["version"].Value, out var version) ||
                version <= installedVersion || selectedVersion is not null && version <= selectedVersion)
            {
                continue;
            }

            if (!release.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array ||
                !TryGetAsset(assets, $"ClaudeDesktopGuardian-{match.Groups["version"].Value}-windows-x64.zip", out var packageUri) ||
                !TryGetAsset(assets, "SHA256SUMS-release.txt", out var checksumsUri) ||
                !TryGetString(release, "html_url", out var releaseUrl) ||
                !Uri.TryCreate(releaseUrl, UriKind.Absolute, out var releaseUri) ||
                releaseUri.Host != "github.com" || releaseUri.Scheme != Uri.UriSchemeHttps)
            {
                continue;
            }

            selected = new GuardianUpdate(
                match.Groups["version"].Value,
                $"ClaudeDesktopGuardian-{match.Groups["version"].Value}-windows-x64.zip",
                packageUri,
                checksumsUri,
                releaseUri);
            selectedVersion = version;
        }

        return selected;
    }

    public static string ParseChecksum(string checksumsText, string packageName)
    {
        var matches = checksumsText.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim().Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries))
            .Where(parts => parts.Length == 2 &&
                            parts[1].TrimStart('*').Equals(packageName, StringComparison.Ordinal))
            .ToArray();
        if (matches.Length != 1 || !Regex.IsMatch(matches[0][0], "^[0-9a-fA-F]{64}$"))
        {
            throw new InvalidDataException("Release 校验清单缺少唯一且有效的更新包 SHA-256");
        }

        return matches[0][0].ToUpperInvariant();
    }

    private async Task<string> DownloadChecksumAsync(GuardianUpdate update, CancellationToken cancellationToken)
    {
        using var response = await GetReleaseAssetAsync(update.ChecksumsUri, cancellationToken);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > 65536)
        {
            throw new InvalidDataException("Release 校验清单超过允许大小");
        }

        var text = await response.Content.ReadAsStringAsync(cancellationToken);
        if (text.Length > 65536)
        {
            throw new InvalidDataException("Release 校验清单超过允许大小");
        }

        return ParseChecksum(text, update.PackageName);
    }

    private static bool TryGetAsset(JsonElement assets, string name, out Uri uri)
    {
        foreach (var asset in assets.EnumerateArray())
        {
            if (TryGetString(asset, "name", out var assetName) && assetName == name &&
                TryGetString(asset, "browser_download_url", out var url) &&
                Uri.TryCreate(url, UriKind.Absolute, out var candidate) &&
                candidate.Scheme == Uri.UriSchemeHttps && candidate.Host == "github.com")
            {
                uri = candidate;
                return true;
            }
        }

        uri = null!;
        return false;
    }

    private static bool TryGetString(JsonElement element, string property, out string value)
    {
        if (element.TryGetProperty(property, out var item) && item.ValueKind == JsonValueKind.String)
        {
            value = item.GetString() ?? string.Empty;
            return !string.IsNullOrWhiteSpace(value);
        }

        value = string.Empty;
        return false;
    }

    private static void ValidateGitHubUri(Uri uri)
    {
        if (uri.Scheme != Uri.UriSchemeHttps || uri.Host != "github.com" ||
            !uri.AbsolutePath.Contains($"/{Repository}/releases/download/", StringComparison.Ordinal))
        {
            throw new InvalidDataException("更新资产必须来自 GitHub HTTPS Release");
        }
    }

    private async Task<HttpResponseMessage> GetReleaseAssetAsync(Uri uri, CancellationToken cancellationToken)
    {
        var currentUri = uri;
        for (var redirect = 0; redirect <= 5; redirect++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, currentUri);
            var response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);
            if ((int)response.StatusCode is < 300 or > 399)
            {
                var responseUri = response.RequestMessage?.RequestUri;
                if (responseUri is null || responseUri.Scheme != Uri.UriSchemeHttps ||
                    !DownloadHosts.Contains(responseUri.Host))
                {
                    response.Dispose();
                    throw new HttpRequestException("GitHub Release 下载最终地址不在允许的 HTTPS 域名内");
                }

                return response;
            }

            var location = response.Headers.Location;
            response.Dispose();
            if (location is null || redirect == 5)
            {
                throw new HttpRequestException("GitHub Release 下载重定向无效或过多");
            }

            currentUri = location.IsAbsoluteUri ? location : new Uri(currentUri, location);
            if (currentUri.Scheme != Uri.UriSchemeHttps || !DownloadHosts.Contains(currentUri.Host))
            {
                throw new HttpRequestException("GitHub Release 下载重定向目标不在允许的 HTTPS 域名内");
            }
        }

        throw new HttpRequestException("GitHub Release 下载重定向超过限制");
    }
}
