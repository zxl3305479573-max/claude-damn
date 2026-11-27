using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClaudeDesktopGuardian.Core;

public static class FingerprintInspector
{
    private static readonly Regex RegionalFontRegex = new(
        @"simsun|simhei|simkai|simfang|msyh|msjh|dengxian|wqy|fzshu|fzkai|fzhei|fangsong",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex VirtualGpuRegex = new(
        @"Virtual|VMware|VirtualBox|SwiftShader|llvmpipe|Microsoft Basic",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex VirtualMachineRegex = new(
        @"VMware|VirtualBox|QEMU|KVM|Parallels|HVM|Hyper-V",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static string RunReport()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# 设备指纹体检（只读） {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

        var hits = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var fontDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Fonts"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "Fonts")
        };

        foreach (var dir in fontDirs)
        {
            if (!Directory.Exists(dir))
            {
                continue;
            }

            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.*", SearchOption.AllDirectories))
                {
                    var ext = Path.GetExtension(file);
                    if (!ext.Equals(".ttf", StringComparison.OrdinalIgnoreCase) &&
                        !ext.Equals(".ttc", StringComparison.OrdinalIgnoreCase) &&
                        !ext.Equals(".otf", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var name = Path.GetFileName(file);
                    if (RegionalFontRegex.IsMatch(name))
                    {
                        hits.Add(name.ToLowerInvariant());
                    }
                }
            }
            catch
            {
            }
        }

        if (hits.Count > 0)
        {
            sb.AppendLine($"[警告] 地区特征字体：检测到 {hits.Count} 个（{string.Join(", ", hits.OrderBy(x => x).Take(20))}）");
            sb.AppendLine("       提示：系统自带字体不等于异常，不需要的字体可在 Windows 字体设置中停用");
        }
        else
        {
            sb.AppendLine("[通过] 地区特征字体：未发现常见中文办公字体");
        }

        var gpuName = "未知";
        var resolution = "未知";
        var machine = string.Empty;

        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var videoSearcher = new ManagementObjectSearcher(
                    "SELECT Name, CurrentHorizontalResolution, CurrentVerticalResolution FROM Win32_VideoController");
                foreach (var obj in videoSearcher.Get())
                {
                    gpuName = obj["Name"]?.ToString() ?? "未知";
                    var w = obj["CurrentHorizontalResolution"]?.ToString();
                    var h = obj["CurrentVerticalResolution"]?.ToString();
                    if (!string.IsNullOrEmpty(w) && !string.IsNullOrEmpty(h))
                    {
                        resolution = $"{w}x{h}";
                    }
                    break;
                }
            }
            catch
            {
            }

            try
            {
                using var sysSearcher = new ManagementObjectSearcher("SELECT Manufacturer, Model FROM Win32_ComputerSystem");
                foreach (var obj in sysSearcher.Get())
                {
                    machine = $"{obj["Manufacturer"]} {obj["Model"]}".Trim();
                    break;
                }
            }
            catch
            {
            }
        }

        sb.AppendLine($"[信息] GPU：{gpuName}");
        sb.AppendLine($"[信息] 显示分辨率：{resolution}");
        sb.AppendLine($"[信息] 系统区域格式：{CultureInfo.CurrentCulture.Name} / 时区：{TimeZoneInfo.Local.Id}");

        if (VirtualGpuRegex.IsMatch(gpuName) || VirtualMachineRegex.IsMatch(machine))
        {
            sb.AppendLine($"[警告] 虚拟化特征：检测到虚拟化迹象（GPU={gpuName}，机型={machine}）");
        }
        else
        {
            sb.AppendLine("[通过] 虚拟化特征：未发现常见虚拟机/软件渲染特征");
        }

        sb.AppendLine("[提示] Canvas / WebGL 浏览器指纹请使用「一次性安全浏览器」在外部指纹页核对");
        return sb.ToString();
    }
}

public static class CliInspector
{
    public static string RunReport()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# Claude Code CLI 体检（只读） {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

        var cliPath = FindExecutableOnPath("claude", "claude.exe", "claude.cmd");
        if (!string.IsNullOrEmpty(cliPath))
        {
            sb.AppendLine($"[通过] CLI 路径：{cliPath}");
            var version = RunCapture(cliPath, new[] { "--version" }, 4000);
            sb.AppendLine($"[通过] 版本：{(string.IsNullOrEmpty(version) ? "未获取" : version)}");
            var method = cliPath.Contains("\\.claude\\local", StringComparison.OrdinalIgnoreCase) ||
                         cliPath.Contains("\\.local\\share\\claude", StringComparison.OrdinalIgnoreCase)
                ? "native（官方安装脚本）"
                : cliPath.Contains("node_modules", StringComparison.OrdinalIgnoreCase) ||
                  cliPath.Contains("\\.npm", StringComparison.OrdinalIgnoreCase) ||
                  cliPath.Contains("\\.bun", StringComparison.OrdinalIgnoreCase)
                    ? "npm / bun"
                    : "未知（建议核对 PATH）";
            sb.AppendLine($"[信息] 安装方式：{method}");
        }
        else
        {
            sb.AppendLine("[警告] PATH 中未找到 claude 命令");
            sb.AppendLine("[信息] 安装方式：未安装全局 CLI（桌面版可能自带内置 CLI，见下）");
        }

        var install = ClaudeInstallDiscovery.Discover();
        var bundledRoot = Path.Combine(install.ActiveDataPath, "claude-code");
        if (Directory.Exists(bundledRoot))
        {
            var latest = Directory.GetDirectories(bundledRoot)
                .Select(Path.GetFileName)
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .LastOrDefault();
            sb.AppendLine(string.IsNullOrEmpty(latest)
                ? "[信息] 桌面版内置 CLI：目录为空"
                : $"[通过] 桌面版内置 CLI：{latest}");
        }
        else
        {
            sb.AppendLine("[信息] 桌面版内置 CLI：未发现");
        }

        var npmPath = FindExecutableOnPath("npm.cmd", "npm");
        if (!string.IsNullOrEmpty(npmPath))
        {
            var npmOut = RunCapture(npmPath, new[] { "ls", "-g", "--depth=0", "@anthropic-ai/claude-code" }, 6000);
            if (npmOut.Contains("@anthropic-ai/claude-code", StringComparison.OrdinalIgnoreCase))
            {
                sb.AppendLine($"[警告] npm 全局包：{npmOut}");
            }
            else
            {
                sb.AppendLine("[通过] npm 全局包：未检测到重复全局安装");
            }
        }
        else
        {
            sb.AppendLine("[信息] npm 全局包：未检测到 npm");
        }

        var configDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".claude");
        if (Directory.Exists(configDir))
        {
            var totalBytes = MeasureDirectoryBytes(configDir);
            sb.AppendLine($"[通过] 配置目录：{configDir}（{AccountSlotInfo.FormatBytes(totalBytes)}）");
        }
        else
        {
            sb.AppendLine("[信息] 配置目录：未创建（尚未运行过 CLI）");
        }

        sb.AppendLine($"[信息] 桌面版活跃数据目录：{install.ActiveDataPath}");
        if (!string.IsNullOrWhiteSpace(install.PackageFamilyName))
        {
            sb.AppendLine($"[信息] MSIX 包：{install.PackageFamilyName}");
        }

        return sb.ToString();
    }

    private static string? FindExecutableOnPath(params string[] names)
    {
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var dir in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = dir.Trim().Trim('"');
            if (string.IsNullOrEmpty(trimmed) || !Directory.Exists(trimmed))
            {
                continue;
            }

            foreach (var name in names)
            {
                var candidate = Path.Combine(trimmed, name);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        return null;
    }

    private static string RunCapture(string filePath, string[] arguments, int timeoutMs)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = filePath,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            foreach (var arg in arguments)
            {
                psi.ArgumentList.Add(arg);
            }

            using var process = Process.Start(psi);
            if (process is null)
            {
                return string.Empty;
            }

            var outputTask = process.StandardOutput.ReadToEndAsync();
            if (!process.WaitForExit(timeoutMs))
            {
                try { process.Kill(true); } catch { }
                return string.Empty;
            }

            var stdout = outputTask.GetAwaiter().GetResult().Trim();
            return stdout.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    internal static long MeasureDirectoryBytes(string path)
    {
        long total = 0;
        try
        {
            foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                try
                {
                    total += new FileInfo(file).Length;
                }
                catch
                {
                }
            }
        }
        catch
        {
        }

        return total;
    }
}

public static class SafeBrowserLauncher
{
    public sealed record LaunchResult(bool Success, string Message);

    public static LaunchResult Launch(string url, GuardianConfig config, NetworkSnapshot? latestNetwork)
    {
        if (string.IsNullOrWhiteSpace(url) ||
            !Uri.TryCreate(url.Trim(), UriKind.Absolute, out var parsed) ||
            (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps) ||
            Regex.IsMatch(url, @"[\x00-\x20""]"))
        {
            return new LaunchResult(false, "只允许有效的 http:// 或 https:// 链接");
        }

        // Fail-Closed: verify proxy client & TUN path before opening browser
        var (_, clientAlive, _) = WindowsEnvironmentProbe.DetectProxyClient(config.ProxyClientMode);
        var (adapter, _, _, _) = WindowsEnvironmentProbe.FindBestVpnAdapter(config);
        if (adapter is null || !clientAlive)
        {
            return new LaunchResult(false, "代理或 TUN 网卡未就绪，已拒绝打开隔离浏览器以防真实 IP 直连");
        }

        var browserPath = FindChromiumBrowser();
        if (browserPath is null)
        {
            return new LaunchResult(false, "未找到 Chrome / Edge / Brave / Chromium 可执行文件");
        }

        var locale = !string.IsNullOrWhiteSpace(config.ExpectedLocale)
            ? config.ExpectedLocale
            : !string.IsNullOrWhiteSpace(latestNetwork?.ExpectedLocale)
                ? latestNetwork.ExpectedLocale
                : "en-US";
        var profileDir = Path.Combine(Path.GetTempPath(), "cdg-safe-browser-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(profileDir);
            var psi = new ProcessStartInfo
            {
                FileName = browserPath,
                UseShellExecute = false
            };
            psi.ArgumentList.Add($"--user-data-dir={profileDir}");
            psi.ArgumentList.Add("--no-first-run");
            psi.ArgumentList.Add("--no-default-browser-check");
            psi.ArgumentList.Add("--disable-sync");
            psi.ArgumentList.Add("--disable-extensions");
            psi.ArgumentList.Add("--force-webrtc-ip-handling-policy=disable_non_proxied_udp");
            psi.ArgumentList.Add($"--lang={locale.Replace('_', '-')}");
            psi.ArgumentList.Add(parsed.AbsoluteUri);

            var process = Process.Start(psi);
            if (process is null)
            {
                TryDeleteDirectory(profileDir);
                return new LaunchResult(false, "无法启动隔离浏览器进程");
            }

            // Clean up temporary profile automatically after browser closes
            _ = Task.Run(async () =>
            {
                try
                {
                    await process.WaitForExitAsync();
                    await Task.Delay(500);
                }
                catch
                {
                }
                finally
                {
                    process.Dispose();
                    TryDeleteDirectory(profileDir);
                }
            });

            return new LaunchResult(
                true,
                $"已在一次性隔离浏览器打开（{Path.GetFileName(browserPath)}，禁用扩展与非代理 UDP，关闭窗口后自动销毁临时 profile）");
        }
        catch (Exception ex)
        {
            TryDeleteDirectory(profileDir);
            return new LaunchResult(false, $"启动隔离浏览器失败：{ex.Message}");
        }
    }

    private static string? FindChromiumBrowser()
    {
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var candidates = new[]
        {
            Path.Combine(pf, "Google", "Chrome", "Application", "chrome.exe"),
            Path.Combine(pf86, "Google", "Chrome", "Application", "chrome.exe"),
            Path.Combine(local, "Google", "Chrome", "Application", "chrome.exe"),
            Path.Combine(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
            Path.Combine(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
            Path.Combine(local, "Microsoft", "Edge", "Application", "msedge.exe"),
            Path.Combine(pf, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
            Path.Combine(local, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
            Path.Combine(local, "Chromium", "Application", "chrome.exe")
        };
        return candidates.FirstOrDefault(File.Exists);
    }

    private static void TryDeleteDirectory(string path)
    {
        for (var i = 0; i < 4; i++)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    Directory.Delete(path, recursive: true);
                }
                return;
            }
            catch
            {
                Thread.Sleep(300);
            }
        }
    }
}

public static class ProxyDiagnosticsRunner
{
    public sealed record TargetProbeResult(
        string Name,
        string Url,
        bool TransportReached,
        int HttpStatus,
        string Access,
        double ElapsedSeconds,
        string Error);

    public sealed record ProxyDiagnosticsReport(
        int SchemaVersion,
        string Mode,
        string State,
        string Scheme,
        int Port,
        string HostScope,
        bool AuthenticationConfigured,
        IReadOnlyList<TargetProbeResult> Checks,
        string Error = "");

    public static async Task<ProxyDiagnosticsReport> RunAsync(
        string proxyUrl,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(proxyUrl) || Regex.IsMatch(proxyUrl, @"[\s\x00-\x1f\x7f]"))
        {
            return ErrorReport("代理地址不能为空且不能包含空白或控制字符");
        }

        if (!Uri.TryCreate(proxyUrl.Trim(), UriKind.Absolute, out var uri))
        {
            return ErrorReport("代理地址格式无效，请使用 http://、https://、socks5:// 或 socks5h:// 并显式指定端口");
        }

        var scheme = uri.Scheme.ToLowerInvariant();
        if (scheme is not ("http" or "https" or "socks5" or "socks5h") ||
            string.IsNullOrWhiteSpace(uri.Host) ||
            uri.Port < 1 || uri.Port > 65535 ||
            !Regex.IsMatch(proxyUrl.Trim(), @":\d+/?$") ||
            (uri.AbsolutePath is not ("" or "/")) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            return ErrorReport("代理地址必须包含支持的协议（http/https/socks5/socks5h）和显式端口，且不能含路径或查询参数");
        }

        var host = uri.Host.Trim('[', ']');
        var isLoopback = (IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip)) ||
                         host.Equals("localhost", StringComparison.OrdinalIgnoreCase);
        var hostScope = isLoopback ? "loopback" : "remote";
        var hasAuth = !string.IsNullOrEmpty(uri.UserInfo);

        var proxy = new WebProxy(uri)
        {
            BypassProxyOnLocal = false
        };
        if (hasAuth)
        {
            var userInfo = uri.UserInfo.Split(':', 2);
            proxy.Credentials = new NetworkCredential(
                Uri.UnescapeDataString(userInfo[0]),
                userInfo.Length > 1 ? Uri.UnescapeDataString(userInfo[1]) : string.Empty);
        }

        using var handler = new SocketsHttpHandler
        {
            Proxy = proxy,
            UseProxy = true,
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(6)
        };
        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(12)
        };

        var targets = new[]
        {
            ("anthropic_api", "https://api.anthropic.com/v1/models"),
            ("claude_web", "https://claude.ai/")
        };

        var results = new List<TargetProbeResult>();
        foreach (var (name, targetUrl) in targets)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, targetUrl);
                req.Headers.UserAgent.ParseAdd("ClaudeDesktopGuardian/2.0");
                using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                sw.Stop();
                var status = (int)resp.StatusCode;
                var access = status switch
                {
                    401 => "unauthenticated",
                    403 or 407 => "access_restricted",
                    >= 500 => "server_error",
                    _ => "http_response"
                };
                results.Add(new TargetProbeResult(
                    name,
                    targetUrl,
                    TransportReached: true,
                    HttpStatus: status,
                    Access: access,
                    ElapsedSeconds: Math.Round(sw.Elapsed.TotalSeconds, 3),
                    Error: string.Empty));
            }
            catch (Exception ex)
            {
                sw.Stop();
                results.Add(new TargetProbeResult(
                    name,
                    targetUrl,
                    TransportReached: false,
                    HttpStatus: 0,
                    Access: "unknown",
                    ElapsedSeconds: Math.Round(sw.Elapsed.TotalSeconds, 3),
                    Error: $"{ex.GetType().Name}: {ex.Message}"));
            }
        }

        var reachedAll = results.All(r => r.TransportReached);
        return new ProxyDiagnosticsReport(
            SchemaVersion: 1,
            Mode: "proxy_diagnostics",
            State: reachedAll ? "transport_reached" : "transport_failed",
            Scheme: scheme,
            Port: uri.Port,
            HostScope: hostScope,
            AuthenticationConfigured: hasAuth,
            Checks: results);
    }

    public static int GetExitCode(ProxyDiagnosticsReport report) => report.State switch
    {
        "transport_reached" => 0,
        "transport_failed" => 1,
        _ => 2
    };

    public static string? LoadProxyUrlFromConfig(string configPath, out string error)
    {
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(configPath))
        {
            error = "配置文件路径不能为空";
            return null;
        }

        if (!File.Exists(configPath))
        {
            error = $"代理诊断配置文件不存在：{configPath}";
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(configPath, Encoding.UTF8));
            if (doc.RootElement.ValueKind != JsonValueKind.Object ||
                !doc.RootElement.TryGetProperty("proxy_url", out var prop) ||
                prop.ValueKind != JsonValueKind.String)
            {
                error = "配置文件必须为 JSON 对象并包含字符串字段 proxy_url";
                return null;
            }

            var value = prop.GetString()?.Trim();
            if (string.IsNullOrWhiteSpace(value))
            {
                error = "配置文件中的 proxy_url 不能为空";
                return null;
            }

            return value;
        }
        catch (Exception ex)
        {
            error = $"无法解析代理诊断配置文件：{ex.Message}";
            return null;
        }
    }

    public static Task<ProxyDiagnosticsReport> RunFromSourcesAsync(
        string? explicitProxy,
        string? configPath,
        string? envProxy,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(explicitProxy))
        {
            return RunAsync(explicitProxy, cancellationToken);
        }

        if (!string.IsNullOrWhiteSpace(configPath))
        {
            var loaded = LoadProxyUrlFromConfig(configPath, out var configError);
            if (loaded is null)
            {
                return Task.FromResult(ErrorReport(configError));
            }

            return RunAsync(loaded, cancellationToken);
        }

        if (!string.IsNullOrWhiteSpace(envProxy))
        {
            return RunAsync(envProxy, cancellationToken);
        }

        return Task.FromResult(ErrorReport("请通过 --proxy <url>、--config <file.json> 或环境变量 CLAUDE_SWITCHER_PROXY_URL 指定代理地址"));
    }

    public static string FormatReportJson(ProxyDiagnosticsReport report) =>
        JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });

    private static ProxyDiagnosticsReport ErrorReport(string error) =>
        new(1, "proxy_diagnostics", "configuration_error", string.Empty, 0, string.Empty, false, Array.Empty<TargetProbeResult>(), error);
}
