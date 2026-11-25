using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClaudeDesktopGuardian.Core;

public sealed record ClashEndpoint(string BaseUrl, string Secret, string Source);

public sealed record ClashAuditResult(
    string Mode,
    string Status,
    string Detail,
    bool? PinnedRulesLoaded,
    string EndpointSource,
    string EndpointBaseUrl,
    IReadOnlyList<string> HeadRules);

public sealed record ClashRuleFixResult(
    bool Success,
    bool Changed,
    string Message,
    string? BackupPath = null,
    bool FileExisted = false);

public sealed class ClashInspector
{
    public static readonly IReadOnlyList<string> PinnedDomains = new[]
    {
        "claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com",
        "challenges.cloudflare.com", "datadoghq.com", "segment.io", "stripe.com",
        "stripe.network", "stripecdn.com", "intercom.io", "intercomcdn.com", "intercomassets.com"
    };

    public static readonly IReadOnlyList<string> PinnedPorts = new[] { "3478", "5349", "19302" };

    private const string ManagedStart = "// >>> claude-desktop-guardian managed rules >>>";
    private const string ManagedEnd = "// <<< claude-desktop-guardian managed rules <<<";
    private const string LegacyManagedStart = "// >>> claude-switcher managed rules >>>";
    private const string LegacyManagedEnd = "// <<< claude-switcher managed rules <<<";

    private static readonly HttpClient LoopbackHttp = new(new SocketsHttpHandler { UseProxy = false })
    {
        Timeout = TimeSpan.FromSeconds(6)
    };

    public static string FindClashVergeDir()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        foreach (var root in new[]
                 {
                     Path.Combine(appData, "io.github.clash-verge-rev.clash-verge-rev"),
                     Path.Combine(localAppData, "io.github.clash-verge-rev.clash-verge-rev")
                 })
        {
            if (Directory.Exists(root))
            {
                return root;
            }
        }

        return Path.Combine(appData, "io.github.clash-verge-rev.clash-verge-rev");
    }

    public static string? FindFlClashConfigPath()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        foreach (var path in new[]
                 {
                     Path.Combine(appData, "com.follow", "clash", "config.yaml"),
                     Path.Combine(localAppData, "com.follow", "clash", "config.yaml")
                 })
        {
            if (File.Exists(path))
            {
                return path;
            }
        }

        return null;
    }

    public static string ReadClashVergeTunDiagnostic(string proxyClientMode)
    {
        if (!string.Equals(proxyClientMode, ProxyClientModes.ClashVerge, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(proxyClientMode, ProxyClientModes.Auto, StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        var dir = FindClashVergeDir();
        foreach (var name in new[] { "config.yaml", "clash-verge.yaml" })
        {
            var path = Path.Combine(dir, name);
            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                var inTun = false;
                foreach (var line in File.ReadLines(path, Encoding.UTF8))
                {
                    if (Regex.IsMatch(line, @"^tun:\s*$"))
                    {
                        inTun = true;
                        continue;
                    }

                    if (inTun && Regex.IsMatch(line, @"^\S"))
                    {
                        break;
                    }

                    var match = Regex.Match(line, @"^\s+enable:\s*(true|false)\s*$");
                    if (inTun && match.Success)
                    {
                        return match.Groups[1].Value.Equals("false", StringComparison.OrdinalIgnoreCase)
                            ? $"Clash Verge 运行配置 {name} 的 tun.enable=false"
                            : string.Empty;
                    }
                }
            }
            catch
            {
            }
        }

        return string.Empty;
    }

    public static string DetectDefaultProxyGroup(string? clashDirOverride = null)
    {
        var dir = clashDirOverride ?? FindClashVergeDir();
        foreach (var fileName in new[] { "clash-verge.yaml", "config.yaml" })
        {
            var path = Path.Combine(dir, fileName);
            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                var inGroups = false;
                string? pendingName = null;
                var pendingIsSelect = false;

                foreach (var rawLine in File.ReadLines(path, Encoding.UTF8))
                {
                    if (Regex.IsMatch(rawLine, @"^proxy-groups:\s*$"))
                    {
                        inGroups = true;
                        continue;
                    }

                    if (!inGroups)
                    {
                        continue;
                    }

                    if (Regex.IsMatch(rawLine, @"^\S"))
                    {
                        break;
                    }

                    var itemStart = Regex.Match(rawLine, @"^\s*-\s*(.*)$");
                    if (itemStart.Success)
                    {
                        if (!string.IsNullOrWhiteSpace(pendingName) && pendingIsSelect)
                        {
                            return pendingName;
                        }

                        pendingName = null;
                        pendingIsSelect = false;
                        var rest = itemStart.Groups[1].Value;
                        var inlineName = Regex.Match(rest, @"name\s*:\s*(['""]?)(.+?)\1(?:\s*,|\s*\}|\s*$)");
                        if (inlineName.Success)
                        {
                            pendingName = inlineName.Groups[2].Value.Trim();
                        }

                        if (Regex.IsMatch(rest, @"type\s*:\s*['""]?select['""]?(?:\s*,|\s*\}|\s*$)", RegexOptions.IgnoreCase))
                        {
                            pendingIsSelect = true;
                        }

                        if (!string.IsNullOrWhiteSpace(pendingName) && pendingIsSelect)
                        {
                            return pendingName;
                        }

                        continue;
                    }

                    var nameMatch = Regex.Match(rawLine, @"^\s+name\s*:\s*(.*?)\s*$");
                    if (nameMatch.Success)
                    {
                        pendingName = Regex.Replace(nameMatch.Groups[1].Value.Trim(), @"\s+#.*$", string.Empty).Trim('"', '\'');
                    }

                    var typeMatch = Regex.Match(rawLine, @"^\s+type\s*:\s*['""]?(\w+)['""]?", RegexOptions.IgnoreCase);
                    if (typeMatch.Success && typeMatch.Groups[1].Value.Equals("select", StringComparison.OrdinalIgnoreCase))
                    {
                        pendingIsSelect = true;
                    }

                    if (!string.IsNullOrWhiteSpace(pendingName) && pendingIsSelect)
                    {
                        return pendingName;
                    }
                }
            }
            catch
            {
            }
        }

        return "GLOBAL";
    }

    public async Task<ClashRuleFixResult> RepairClashVergeRulesAsync(
        GuardianConfig config,
        CancellationToken cancellationToken)
    {
        var dir = FindClashVergeDir();
        if (!Directory.Exists(dir))
        {
            return new ClashRuleFixResult(false, false, $"未找到 Clash Verge 配置目录：{dir}");
        }

        var cleanup = CleanupLegacyMergeRules(dir);
        var endpoint = await ResolveEndpointAsync(config, preferFlClash: false, cancellationToken);
        var mode = await DetectClashModeAsync(endpoint, isFlClash: false, cancellationToken);
        var policy = WebRtcPolicies.Normalize(config.WebRtcPolicy);

        if (mode == "global")
        {
            var msg = cleanup.Changed
                ? $"Clash 当前为全局模式，跳过写入 Script.js；{cleanup.Message}"
                : "Clash 当前为全局模式（全部流量已走代理），无需写入 Script.js";
            return new ClashRuleFixResult(true, cleanup.Changed, msg, cleanup.BackupPath);
        }

        if (mode == "direct")
        {
            var msg = "Clash 当前处于直连模式（direct），已拒绝写入规则；请先切换到规则模式或全局模式";
            if (cleanup.Changed)
            {
                msg += $"（{cleanup.Message}）";
            }

            return new ClashRuleFixResult(false, cleanup.Changed, msg, cleanup.BackupPath);
        }

        if (mode == "unknown")
        {
            var msg = "无法确认 Clash 运行模式，跳过修改 Script.js 以免误伤配置";
            if (cleanup.Changed)
            {
                msg += $"（{cleanup.Message}）";
            }

            return new ClashRuleFixResult(false, cleanup.Changed, msg, cleanup.BackupPath);
        }

        var proxyGroup = string.IsNullOrWhiteSpace(config.ClashProxyGroup) ||
                         config.ClashProxyGroup.Equals("GLOBAL", StringComparison.OrdinalIgnoreCase)
            ? DetectDefaultProxyGroup(dir)
            : config.ClashProxyGroup.Trim();

        var write = WriteClashVergePinnedRules(proxyGroup, policy, dir);
        if (!write.Success)
        {
            return write;
        }

        var details = new List<string> { write.Message };
        if (cleanup.Changed)
        {
            details.Add(cleanup.Message);
        }

        if (write.Changed && TryRestartClashVerge())
        {
            details.Add("已重启 Clash Verge 加载新规则");
            var verified = await WaitForPinnedRulesVerificationAsync(config, policy, cancellationToken);
            if (verified == true)
            {
                details.Add($"内核 /rules 前 16 条置顶规则验证通过（策略 {policy}）");
                return new ClashRuleFixResult(true, true, string.Join("；", details), write.BackupPath, write.FileExisted);
            }

            if (verified == false)
            {
                RollbackScriptJs(dir, write);
                return new ClashRuleFixResult(
                    false,
                    false,
                    "重启 Clash Verge 后内核 /rules 未加载全部 16 条置顶规则（请确认已启用「全局扩展脚本」且代理组名有效），已自动回滚 Script.js",
                    write.BackupPath,
                    write.FileExisted);
            }

            details.Add("控制接口暂不可达，未能验证内核 /rules 加载状态");
        }
        else if (endpoint is not null)
        {
            var (ok, _, rules) = await FetchRulesAsync(endpoint, cancellationToken);
            if (ok && ArePinnedRulesLoaded(rules, policy))
            {
                details.Add($"内核 /rules 前 16 条已确认加载（策略 {policy}）");
            }
            else if (write.Changed)
            {
                details.Add("请在 Clash Verge 中重载配置以使 Script.js 置顶规则生效");
            }
        }

        return new ClashRuleFixResult(true, write.Changed || cleanup.Changed, string.Join("；", details), write.BackupPath, write.FileExisted);
    }

    private async Task<bool?> WaitForPinnedRulesVerificationAsync(
        GuardianConfig config,
        string webrtcPolicy,
        CancellationToken cancellationToken)
    {
        bool? lastVerdict = null;
        for (var attempt = 0; attempt < 8; attempt++)
        {
            await Task.Delay(1500, cancellationToken);
            var endpoint = await ResolveEndpointAsync(config, preferFlClash: false, cancellationToken);
            if (endpoint is null)
            {
                continue;
            }

            var (ok, _, rules) = await FetchRulesAsync(endpoint, cancellationToken);
            if (!ok)
            {
                continue;
            }

            if (ArePinnedRulesLoaded(rules, webrtcPolicy))
            {
                return true;
            }

            lastVerdict = false;
        }

        return lastVerdict;
    }

    private static void RollbackScriptJs(string clashDir, ClashRuleFixResult write)
    {
        var scriptPath = Path.Combine(clashDir, "profiles", "Script.js");
        try
        {
            if (!string.IsNullOrEmpty(write.BackupPath) && File.Exists(write.BackupPath))
            {
                File.Copy(write.BackupPath, scriptPath, overwrite: true);
            }
            else if (!write.FileExisted && File.Exists(scriptPath))
            {
                File.Delete(scriptPath);
            }
        }
        catch
        {
        }
    }

    private static bool TryRestartClashVerge()
    {
        var exe = FindClashVergeExecutable();
        if (string.IsNullOrWhiteSpace(exe))
        {
            return false;
        }

        var running = Process.GetProcessesByName("clash-verge")
            .Concat(Process.GetProcessesByName("Clash Verge"))
            .ToArray();
        if (running.Length == 0)
        {
            return false;
        }

        foreach (var proc in running)
        {
            try { proc.Kill(true); } catch { }
            proc.Dispose();
        }

        Thread.Sleep(1500);
        try
        {
            Process.Start(new ProcessStartInfo { FileName = exe, UseShellExecute = true });
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string? FindClashVergeExecutable()
    {
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var candidates = new[]
        {
            Path.Combine(pf, "Clash Verge", "clash-verge.exe"),
            Path.Combine(local, "Programs", "Clash Verge", "clash-verge.exe"),
            Path.Combine(local, "Clash Verge", "clash-verge.exe")
        };
        return candidates.FirstOrDefault(File.Exists);
    }

    public async Task<ClashAuditResult> InspectAsync(
        GuardianConfig config,
        CancellationToken cancellationToken)
    {
        var modeKey = ProxyClientModes.Normalize(config.ProxyClientMode);
        var webrtcPolicy = WebRtcPolicies.Normalize(config.WebRtcPolicy);
        var isFlClash = IsFlClashActive(modeKey);
        var isClashFamily = modeKey is ProxyClientModes.ClashVerge or ProxyClientModes.FlClash ||
                            (modeKey == ProxyClientModes.Auto && (isFlClash || Directory.Exists(FindClashVergeDir())));
        if (!isClashFamily)
        {
            return new ClashAuditResult(
                "n/a",
                "warn",
                $"当前代理客户端为 {ProxyClientModes.DisplayName(modeKey)}，请在客户端内自行确认 Claude 域名分流",
                null,
                string.Empty,
                string.Empty,
                Array.Empty<string>());
        }

        var endpoint = await ResolveEndpointAsync(config, isFlClash, cancellationToken);
        var clashMode = await DetectClashModeAsync(endpoint, isFlClash, cancellationToken);

        if (clashMode == "global")
        {
            return new ClashAuditResult(
                "global",
                "ok",
                "全局模式（所有流量走代理，置顶规则无需介入）",
                true,
                endpoint?.Source ?? string.Empty,
                endpoint?.BaseUrl ?? string.Empty,
                Array.Empty<string>());
        }

        if (clashMode == "direct")
        {
            return new ClashAuditResult(
                "direct",
                "fail",
                "Clash 当前处于直连模式（direct），存在直连泄漏风险",
                false,
                endpoint?.Source ?? string.Empty,
                endpoint?.BaseUrl ?? string.Empty,
                Array.Empty<string>());
        }

        if (clashMode == "unknown")
        {
            return new ClashAuditResult(
                "unknown",
                "warn",
                "无法确认 Clash 运行模式（未读取到控制接口或配置文件）",
                null,
                endpoint?.Source ?? string.Empty,
                endpoint?.BaseUrl ?? string.Empty,
                Array.Empty<string>());
        }

        var (ok, reason, rules) = await FetchRulesAsync(endpoint, cancellationToken);
        if (ok)
        {
            var pinned = ArePinnedRulesLoaded(rules, webrtcPolicy);
            var headPreview = rules.Take(18).Select(rule => $"{rule.Type},{rule.Payload},{rule.Proxy}").ToArray();
            return pinned
                ? new ClashAuditResult(
                    "rule",
                    "ok",
                    $"规则模式：内核前 16 条已加载全部 13 个 Claude 域名 + 3 个 STUN UDP 端口（策略 {webrtcPolicy}，来源 {endpoint?.Source}）",
                    true,
                    endpoint?.Source ?? string.Empty,
                    endpoint?.BaseUrl ?? string.Empty,
                    headPreview)
                : new ClashAuditResult(
                    "rule",
                    "fail",
                    $"规则模式：内核前 16 条未加载完整 Claude 置顶规则或端口目标不符合策略（{webrtcPolicy}）",
                    false,
                    endpoint?.Source ?? string.Empty,
                    endpoint?.BaseUrl ?? string.Empty,
                    headPreview);
        }

        var hint = FormatApiHint(reason, isFlClash);
        if (!isFlClash && HasManagedScriptRules())
        {
            return new ClashAuditResult(
                "rule",
                "warn",
                $"Script.js 托管规则已写入，但无法验证内核加载（{hint}）",
                null,
                endpoint?.Source ?? string.Empty,
                endpoint?.BaseUrl ?? string.Empty,
                Array.Empty<string>());
        }

        return new ClashAuditResult(
            "rule",
            "fail",
            $"未验证到置顶规则（{hint}）",
            false,
            endpoint?.Source ?? string.Empty,
            endpoint?.BaseUrl ?? string.Empty,
            Array.Empty<string>());
    }

    public static bool ArePinnedRulesLoaded(
        IReadOnlyList<ClashRuleEntry> rules,
        string webrtcPolicy = WebRtcPolicies.Proxy)
    {
        var head = rules.Take(16).ToArray();
        if (head.Length < 16)
        {
            return false;
        }

        var wantReject = string.Equals(WebRtcPolicies.Normalize(webrtcPolicy), WebRtcPolicies.Reject, StringComparison.Ordinal);
        var domainHits = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var portHits = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in head)
        {
            var proxyTarget = rule.Proxy?.Trim() ?? string.Empty;
            var isDirect = proxyTarget.Equals("DIRECT", StringComparison.OrdinalIgnoreCase);
            var isReject = proxyTarget.Equals("REJECT", StringComparison.OrdinalIgnoreCase);
            var normalizedType = rule.Type.Replace("-", string.Empty, StringComparison.Ordinal)
                .Replace("_", string.Empty, StringComparison.Ordinal)
                .ToLowerInvariant();
            if (normalizedType == "domainsuffix" &&
                PinnedDomains.Contains(rule.Payload, StringComparer.OrdinalIgnoreCase))
            {
                if (!isDirect && !isReject && !string.IsNullOrEmpty(proxyTarget))
                {
                    domainHits.Add(rule.Payload);
                }
            }
            else if (normalizedType == "dstport" &&
                     PinnedPorts.Contains(rule.Payload, StringComparer.OrdinalIgnoreCase))
            {
                if (wantReject ? isReject : (!isDirect && !isReject && !string.IsNullOrEmpty(proxyTarget)))
                {
                    portHits.Add(rule.Payload);
                }
            }
            else
            {
                foreach (var port in PinnedPorts)
                {
                    if (Regex.IsMatch(rule.Payload, $@"DST-PORT,{Regex.Escape(port)}(?:[,)]|$)", RegexOptions.IgnoreCase))
                    {
                        if (wantReject ? isReject : (!isDirect && !isReject && !string.IsNullOrEmpty(proxyTarget)))
                        {
                            portHits.Add(port);
                        }
                    }
                }
            }
        }

        return domainHits.Count == PinnedDomains.Count && portHits.Count == PinnedPorts.Count;
    }

    public static bool HasManagedScriptRules(string? clashDirOverride = null)
    {
        var scriptPath = Path.Combine(clashDirOverride ?? FindClashVergeDir(), "profiles", "Script.js");
        if (!File.Exists(scriptPath))
        {
            return false;
        }

        try
        {
            var content = File.ReadAllText(scriptPath, Encoding.UTF8);
            return content.Contains(ManagedStart, StringComparison.Ordinal) ||
                   content.Contains(LegacyManagedStart, StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    public static ClashRuleFixResult WriteClashVergePinnedRules(
        string proxyGroup,
        string webrtcPolicy = WebRtcPolicies.Proxy,
        string? clashDirOverride = null)
    {
        if (string.IsNullOrWhiteSpace(proxyGroup) || proxyGroup.IndexOfAny(new[] { ',', '\r', '\n' }) >= 0)
        {
            return new ClashRuleFixResult(false, false, "Clash 代理组名为空或包含非法字符");
        }

        var dir = clashDirOverride ?? FindClashVergeDir();
        if (!Directory.Exists(dir))
        {
            return new ClashRuleFixResult(false, false, $"未找到 Clash Verge 配置目录：{dir}");
        }

        var scriptPath = Path.Combine(dir, "profiles", "Script.js");
        var existed = File.Exists(scriptPath);
        string? backupPath = null;
        var normalizedPolicy = WebRtcPolicies.Normalize(webrtcPolicy);
        var portTarget = normalizedPolicy == WebRtcPolicies.Reject ? "REJECT" : proxyGroup.Trim();

        try
        {
            var rules = PinnedDomains.Select(d => $"DOMAIN-SUFFIX,{d},{proxyGroup.Trim()}")
                .Concat(PinnedPorts.Select(p => $"AND,((NETWORK,UDP),(DST-PORT,{p})),{portTarget}"))
                .ToArray();
            var json = JsonSerializer.Serialize(rules);

            var wrapperBlock =
                $"{ManagedStart}\r\n" +
                "const __cdgOrigMain = main;\r\n" +
                "main = function (config, profileName) {\r\n" +
                "  const __cdgCfg = __cdgOrigMain(config, profileName);\r\n" +
                "  if (__cdgCfg && typeof __cdgCfg === 'object') {\r\n" +
                $"    const __cdgPinned = {json};\r\n" +
                "    const __cdgExisting = Array.isArray(__cdgCfg.rules) ? __cdgCfg.rules : [];\r\n" +
                "    __cdgCfg.rules = __cdgPinned.concat(__cdgExisting.filter(r => !__cdgPinned.includes(r)));\r\n" +
                "  }\r\n" +
                "  return __cdgCfg;\r\n" +
                "};\r\n" +
                ManagedEnd;

            if (!existed)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(scriptPath)!);
                var content = $"function main(config, profileName) {{\r\n  return config;\r\n}}\r\n\r\n{wrapperBlock}\r\n";
                File.WriteAllText(scriptPath, content, new UTF8Encoding(false));
                return new ClashRuleFixResult(true, true, $"已创建 profiles\\Script.js 并写入 16 条置顶规则（代理组：{proxyGroup.Trim()}，STUN 策略：{normalizedPolicy}）", FileExisted: false);
            }

            var existing = File.ReadAllText(scriptPath, Encoding.UTF8);
            if (!Regex.IsMatch(existing, @"function\s+main\s*\("))
            {
                return new ClashRuleFixResult(false, false, "Script.js 已存在但缺少 function main(...)，未自动改写", FileExisted: true);
            }

            var stripped = existing;
            stripped = Regex.Replace(stripped, @"(?:\r?\n)*" + Regex.Escape(ManagedStart) + ".*?" + Regex.Escape(ManagedEnd) + @"(?:\r?\n)*", "\r\n", RegexOptions.Singleline);
            stripped = Regex.Replace(stripped, @"(?:\r?\n)*" + Regex.Escape(LegacyManagedStart) + ".*?" + Regex.Escape(LegacyManagedEnd) + @"(?:\r?\n)*", "\r\n", RegexOptions.Singleline);
            stripped = stripped.TrimEnd('\r', '\n');

            var updated = stripped + "\r\n\r\n" + wrapperBlock + "\r\n";
            if (string.Equals(updated, existing, StringComparison.Ordinal))
            {
                return new ClashRuleFixResult(true, false, "Script.js 置顶规则已是最新，无需改动", FileExisted: true);
            }

            backupPath = $"{scriptPath}.bak.{DateTime.Now:yyyyMMddHHmmss}";
            File.Copy(scriptPath, backupPath, overwrite: true);
            File.WriteAllText(scriptPath, updated, new UTF8Encoding(false));
            return new ClashRuleFixResult(true, true, $"已写入 Script.js 置顶规则（代理组：{proxyGroup.Trim()}，STUN 策略：{normalizedPolicy}，已备份到 {Path.GetFileName(backupPath)}）", backupPath, FileExisted: true);
        }
        catch (Exception ex)
        {
            if (!string.IsNullOrEmpty(backupPath) && File.Exists(backupPath))
            {
                try { File.Copy(backupPath, scriptPath, overwrite: true); } catch { }
            }
            else if (!existed && File.Exists(scriptPath))
            {
                try { File.Delete(scriptPath); } catch { }
            }

            return new ClashRuleFixResult(false, false, $"写入 Script.js 失败：{ex.Message}", FileExisted: existed);
        }
    }

    public static ClashRuleFixResult CleanupLegacyMergeRules(string? clashDirOverride = null)
    {
        var mergePath = Path.Combine(clashDirOverride ?? FindClashVergeDir(), "profiles", "Merge.yaml");
        if (!File.Exists(mergePath))
        {
            return new ClashRuleFixResult(true, false, string.Empty);
        }

        string? backupPath = null;
        try
        {
            var lines = File.ReadAllLines(mergePath, Encoding.UTF8);
            var domainAlt = string.Join("|", PinnedDomains.Select(Regex.Escape));
            var portAlt = string.Join("|", PinnedPorts.Select(Regex.Escape));
            var ruleRegex = new Regex(
                $@"^\s*-\s*((DOMAIN-SUFFIX,({domainAlt}),)|(DST-PORT,({portAlt}),)|(AND,\(\(NETWORK,UDP\),\(DST-PORT,({portAlt})\)\),))",
                RegexOptions.IgnoreCase);
            var docSepRegex = new Regex(@"^\s*---\s*(#.*)?$");
            var prependHeaderRegex = new Regex(@"^\s*prepend-rules:\s*(#.*)?$");
            var topKeyRegex = new Regex(@"^([A-Za-z0-9_.-]+):");

            var removedRules = 0;
            var removedDocs = 0;
            var step1 = new List<string>(lines.Length);
            foreach (var line in lines)
            {
                if (docSepRegex.IsMatch(line))
                {
                    removedDocs++;
                    continue;
                }

                if (ruleRegex.IsMatch(line))
                {
                    removedRules++;
                    continue;
                }

                step1.Add(line);
            }

            var step2 = new List<string>(step1.Count);
            var removedEmptyPrepend = 0;
            for (var i = 0; i < step1.Count; i++)
            {
                var line = step1[i];
                if (prependHeaderRegex.IsMatch(line))
                {
                    var hasItem = false;
                    for (var j = i + 1; j < step1.Count; j++)
                    {
                        var next = step1[j];
                        if (string.IsNullOrWhiteSpace(next) || Regex.IsMatch(next, @"^\s*#"))
                        {
                            continue;
                        }

                        if (Regex.IsMatch(next, @"^\s*-\s+"))
                        {
                            hasItem = true;
                        }

                        break;
                    }

                    if (!hasItem)
                    {
                        removedEmptyPrepend++;
                        continue;
                    }
                }

                step2.Add(line);
            }

            var finalLines = new List<string>(step2.Count);
            var seenTopKeys = new HashSet<string>(StringComparer.Ordinal);
            var skippingDupeSection = false;
            var removedDupes = 0;
            foreach (var line in step2)
            {
                var m = topKeyRegex.Match(line);
                if (m.Success)
                {
                    var key = m.Groups[1].Value;
                    if (!seenTopKeys.Add(key))
                    {
                        skippingDupeSection = true;
                        removedDupes++;
                        continue;
                    }

                    skippingDupeSection = false;
                    finalLines.Add(line);
                    continue;
                }

                if (skippingDupeSection)
                {
                    continue;
                }

                finalLines.Add(line);
            }

            var before = string.Join("\n", lines);
            var after = string.Join("\n", finalLines);
            if (string.Equals(before, after, StringComparison.Ordinal))
            {
                return new ClashRuleFixResult(true, false, string.Empty);
            }

            backupPath = $"{mergePath}.bak.{DateTime.Now:yyyyMMddHHmmss}";
            File.Copy(mergePath, backupPath, overwrite: true);
            if (string.IsNullOrWhiteSpace(after))
            {
                File.Delete(mergePath);
            }
            else
            {
                File.WriteAllText(mergePath, string.Join("\r\n", finalLines) + "\r\n", new UTF8Encoding(false));
            }

            return new ClashRuleFixResult(
                true,
                true,
                $"已清理 Merge.yaml 历史遗留（规则 {removedRules} 条、分隔符 {removedDocs}、空头 {removedEmptyPrepend}、重复键 {removedDupes}，备份：{Path.GetFileName(backupPath)}）",
                backupPath);
        }
        catch (Exception ex)
        {
            if (!string.IsNullOrEmpty(backupPath) && File.Exists(backupPath))
            {
                try { File.Copy(backupPath, mergePath, overwrite: true); } catch { }
            }

            return new ClashRuleFixResult(false, false, $"清理 Merge.yaml 失败：{ex.Message}");
        }
    }

    private static bool IsFlClashActive(string proxyMode)
    {
        if (proxyMode == ProxyClientModes.FlClash)
        {
            return true;
        }

        if (proxyMode != ProxyClientModes.Auto)
        {
            return false;
        }

        return Process.GetProcessesByName("FlClashCore").Length > 0 ||
               Process.GetProcessesByName("FlClash").Length > 0;
    }

    private static async Task<ClashEndpoint?> ResolveEndpointAsync(
        GuardianConfig config,
        bool preferFlClash,
        CancellationToken cancellationToken)
    {
        if (preferFlClash)
        {
            return await ResolveFlClashEndpointAsync(config.FlClashController, cancellationToken);
        }

        var dir = FindClashVergeDir();
        foreach (var fileName in new[] { "clash-verge.yaml", "config.yaml", "verge.yaml" })
        {
            var path = Path.Combine(dir, fileName);
            var rawAddr = ReadYamlScalar(path, "external-controller");
            var normalized = ClashEndpointValidator.NormalizeLoopbackEndpoint(rawAddr);
            if (normalized is not null)
            {
                var secret = ReadYamlScalar(path, "secret") ?? string.Empty;
                return new ClashEndpoint("http://" + normalized, secret, fileName);
            }
        }

        if (ProxyClientModes.Normalize(config.ProxyClientMode) == ProxyClientModes.Auto)
        {
            return await ResolveFlClashEndpointAsync(config.FlClashController, cancellationToken);
        }

        return null;
    }

    private static async Task<ClashEndpoint?> ResolveFlClashEndpointAsync(
        string? controllerOverride,
        CancellationToken cancellationToken)
    {
        var yaml = FindFlClashConfigPath();
        var secret = yaml is not null ? ReadYamlScalar(yaml, "secret") ?? string.Empty : string.Empty;

        var normalizedOverride = ClashEndpointValidator.NormalizeLoopbackEndpoint(controllerOverride);
        if (normalizedOverride is not null)
        {
            return new ClashEndpoint("http://" + normalizedOverride, secret, "flclash-override");
        }

        if (yaml is not null)
        {
            var rawAddr = ReadYamlScalar(yaml, "external-controller");
            if (!string.IsNullOrWhiteSpace(rawAddr))
            {
                var normalized = ClashEndpointValidator.NormalizeLoopbackEndpoint(rawAddr);
                return normalized is not null
                    ? new ClashEndpoint("http://" + normalized, secret, "flclash-config")
                    : null;
            }
        }

        var candidates = new List<(string Endpoint, string Source)> { ("127.0.0.1:9090", "flclash-9090") };
        foreach (var listened in GetFlClashLoopbackListenEndpoints())
        {
            if (!candidates.Any(c => c.Endpoint.Equals(listened, StringComparison.OrdinalIgnoreCase)))
            {
                candidates.Add((listened, "flclash-listen"));
            }
        }

        foreach (var (candidateAddr, source) in candidates)
        {
            var probe = new ClashEndpoint("http://" + candidateAddr, secret, source);
            if (await TestVersionEndpointAsync(probe, cancellationToken))
            {
                return probe;
            }
        }

        return null;
    }

    private static IReadOnlyList<string> GetFlClashLoopbackListenEndpoints()
    {
        if (!OperatingSystem.IsWindows())
        {
            return Array.Empty<string>();
        }

        try
        {
            var pids = new HashSet<uint>();
            foreach (var name in new[] { "FlClashCore", "FlClash" })
            {
                foreach (var proc in Process.GetProcessesByName(name))
                {
                    try { pids.Add((uint)proc.Id); } catch { }
                    proc.Dispose();
                }
            }

            if (pids.Count == 0)
            {
                return Array.Empty<string>();
            }

            var size = 0;
            // AF_INET = 2, TCP_TABLE_OWNER_PID_LISTENER = 3
            _ = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2, 3, 0);
            if (size <= 0)
            {
                return Array.Empty<string>();
            }

            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(buffer, ref size, true, 2, 3, 0) != 0)
                {
                    return Array.Empty<string>();
                }

                var count = Marshal.ReadInt32(buffer);
                var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
                var current = buffer + sizeof(int);
                var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                for (var i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(current);
                    current += rowSize;
                    if (!pids.Contains(row.ProcessId))
                    {
                        continue;
                    }

                    var localIp = new IPAddress(row.LocalAddress);
                    if (!IPAddress.IsLoopback(localIp) && !localIp.Equals(IPAddress.Any))
                    {
                        continue;
                    }

                    var port = (ushort)IPAddress.NetworkToHostOrder((short)row.LocalPort);
                    if (port is > 0 and <= 65535)
                    {
                        results.Add($"127.0.0.1:{port}");
                    }
                }

                return results.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable,
        ref int bufferLength,
        bool sort,
        int addressFamily,
        int tableClass,
        uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint ProcessId;
    }

    private static async Task<bool> TestVersionEndpointAsync(ClashEndpoint endpoint, CancellationToken cancellationToken)
    {
        try
        {
            using var request = CreateApiRequest(endpoint, "/version");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            using var response = await LoopbackHttp.SendAsync(request, timeout.Token);
            if (!response.IsSuccessStatusCode)
            {
                return false;
            }

            var body = await response.Content.ReadAsStringAsync(timeout.Token);
            return body.Contains("version", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static async Task<string> DetectClashModeAsync(
        ClashEndpoint? endpoint,
        bool isFlClash,
        CancellationToken cancellationToken)
    {
        if (endpoint is not null)
        {
            try
            {
                using var request = CreateApiRequest(endpoint, "/configs");
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(3));
                using var response = await LoopbackHttp.SendAsync(request, timeout.Token);
                if (response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadAsStringAsync(timeout.Token);
                    using var doc = JsonDocument.Parse(body);
                    if (doc.RootElement.TryGetProperty("mode", out var modeProp))
                    {
                        var mode = modeProp.GetString()?.Trim().ToLowerInvariant();
                        if (mode is "global" or "rule" or "direct")
                        {
                            return mode;
                        }
                    }
                }
            }
            catch
            {
            }
        }

        if (!isFlClash)
        {
            var dir = FindClashVergeDir();
            foreach (var fileName in new[] { "clash-verge.yaml", "config.yaml", "verge.yaml" })
            {
                var mode = ReadYamlScalar(Path.Combine(dir, fileName), "mode")?.ToLowerInvariant();
                if (mode is "global" or "rule" or "direct")
                {
                    return mode;
                }
            }
        }

        var flPath = FindFlClashConfigPath();
        if (flPath is not null)
        {
            var mode = ReadYamlScalar(flPath, "mode")?.ToLowerInvariant();
            if (mode is "global" or "rule" or "direct")
            {
                return mode;
            }
        }

        return "unknown";
    }

    private static async Task<(bool Ok, string Reason, IReadOnlyList<ClashRuleEntry> Rules)> FetchRulesAsync(
        ClashEndpoint? endpoint,
        CancellationToken cancellationToken)
    {
        if (endpoint is null)
        {
            return (false, "no-endpoint", Array.Empty<ClashRuleEntry>());
        }

        try
        {
            using var request = CreateApiRequest(endpoint, "/rules");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(6));
            using var response = await LoopbackHttp.SendAsync(request, timeout.Token);
            if ((int)response.StatusCode is 401 or 403)
            {
                return (false, "auth-failed", Array.Empty<ClashRuleEntry>());
            }

            if (!response.IsSuccessStatusCode)
            {
                return (false, $"http-{(int)response.StatusCode}", Array.Empty<ClashRuleEntry>());
            }

            var body = await response.Content.ReadAsStringAsync(timeout.Token);
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("rules", out var rulesProp) ||
                rulesProp.ValueKind != JsonValueKind.Array)
            {
                return (false, "invalid-payload", Array.Empty<ClashRuleEntry>());
            }

            var list = new List<ClashRuleEntry>();
            foreach (var item in rulesProp.EnumerateArray())
            {
                var type = item.TryGetProperty("type", out var t) ? t.GetString() ?? string.Empty : string.Empty;
                var payload = item.TryGetProperty("payload", out var p) ? p.GetString() ?? string.Empty : string.Empty;
                var proxy = item.TryGetProperty("proxy", out var pr) ? pr.GetString() ?? string.Empty : string.Empty;
                list.Add(new ClashRuleEntry(type, payload, proxy));
            }

            return (true, string.Empty, list);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return (false, "timeout", Array.Empty<ClashRuleEntry>());
        }
        catch (HttpRequestException)
        {
            return (false, "connect-failed", Array.Empty<ClashRuleEntry>());
        }
        catch
        {
            return (false, "error", Array.Empty<ClashRuleEntry>());
        }
    }

    private static HttpRequestMessage CreateApiRequest(ClashEndpoint endpoint, string path)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, endpoint.BaseUrl.TrimEnd('/') + path);
        if (!string.IsNullOrWhiteSpace(endpoint.Secret))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", endpoint.Secret);
        }

        return request;
    }

    private static string? ReadYamlScalar(string path, string key)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            var regex = new Regex(@"^\s*" + Regex.Escape(key) + @"\s*:\s*(.*?)\s*$");
            foreach (var line in File.ReadLines(path, Encoding.UTF8))
            {
                var match = regex.Match(line);
                if (!match.Success)
                {
                    continue;
                }

                var value = Regex.Replace(match.Groups[1].Value.Trim(), @"\s+#.*$", string.Empty);
                return value.Trim('"', '\'');
            }
        }
        catch
        {
        }

        return null;
    }

    private static string FormatApiHint(string reason, bool isFlClash) => reason switch
    {
        "no-endpoint" => isFlClash
            ? "控制接口未配置：检查 FlClash external-controller 或在设置里填写本机端口"
            : "控制接口未配置：检查 Clash Verge 的外部控制 external-controller",
        "connect-failed" => isFlClash
            ? "控制接口拒绝连接：FlClash 未开外部控制或端口不对"
            : "控制接口拒绝连接：Clash Verge 未开外部控制或端口不对",
        "auth-failed" => "控制接口鉴权失败：secret 不匹配",
        "timeout" => "控制接口超时：内核无响应或 /rules 列表过大",
        _ => $"控制接口异常（{reason}）"
    };
}

public sealed record ClashRuleEntry(string Type, string Payload, string Proxy);
