using System.Text;
using System.Text.Json;

namespace ClaudeDesktopGuardian.Core;

public sealed class GuardianCliContext
{
    public GuardianConfigStore ConfigStore { get; init; } = new();
    public GuardianStateStore StateStore { get; init; } = new();
    public AccountSlotManager AccountManager { get; init; } = new();
    public GuardianLogger Logger { get; init; } = new();
    public IEnvironmentProbe Probe { get; init; } = new WindowsEnvironmentProbe();
    public IProcessInspector ProcessInspector { get; init; } = new WindowsProcessInspector();
    public ClashInspector ClashInspector { get; init; } = new();
    public TextWriter Out { get; init; } = Console.Out;
    public TextWriter Error { get; init; } = Console.Error;
    public TextReader In { get; init; } = Console.In;
    public Func<string, string?> GetEnvironmentVariable { get; init; } = Environment.GetEnvironmentVariable;
}

/// <summary>
/// Testable command-line dispatcher implementing the claude-switcher (Windows) CLI surface
/// directly on top of ClaudeDesktopGuardian.Core (excluding GitHub auto-update commands).
/// </summary>
public static class GuardianCliRunner
{
    public static async Task<int> RunAsync(
        string[] args,
        GuardianCliContext? context = null,
        CancellationToken cancellationToken = default)
    {
        var ctx = context ?? new GuardianCliContext();
        if (args.Length == 0)
        {
            WriteUsage(ctx.Out);
            return 1;
        }

        var command = args[0].Trim().ToLowerInvariant();
        if (command is "-h" or "--help" or "help")
        {
            WriteUsage(ctx.Out);
            return 0;
        }

        // Standalone proxy diagnostics: NEVER writes client logs or creates account/config state
        if (command == "diagnose-proxy")
        {
            return await RunDiagnoseProxyAsync(args[1..], ctx, cancellationToken);
        }

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var exitCode = 0;
        var config = ctx.ConfigStore.Load();
        IReadOnlyList<CheckResult>? checks = null;

        try
        {
            switch (command)
            {
                case "check":
                case "checkdetail":
                {
                    var engine = new GuardianCheckEngine(ctx.Probe, ctx.ProcessInspector);
                    var report = await engine.RunAsync(config, full: true, cancellationToken);
                    checks = report.Checks;
                    var blocking = ProtectionPolicyEvaluator.GetEffectiveBlockingFailures(report, ctx.StateStore.Load().IgnoreWebRtc);
                    exitCode = blocking.Count == 0 && !report.Network.ProxyPathSkipped ? 0 : 1;
                    if (command == "checkdetail")
                    {
                        foreach (var c in report.Checks)
                        {
                            ctx.Out.WriteLine($"{c.Id}={c.Status.ToString().ToLowerInvariant()}:{c.Detail}");
                        }
                    }
                    else
                    {
                        ctx.Out.WriteLine(exitCode == 0 ? "OK" : $"FAIL:{ProtectionPolicyEvaluator.FormatTripReason(blocking)}");
                    }

                    break;
                }
                case "check-item":
                {
                    if (args.Length != 2 || string.IsNullOrWhiteSpace(args[1]))
                    {
                        ctx.Error.WriteLine("用法: check-item <check-id>");
                        return 1;
                    }

                    var targetId = args[1].Trim().ToLowerInvariant();
                    var engine = new GuardianCheckEngine(ctx.Probe, ctx.ProcessInspector);
                    var baseline = new GuardianReport(
                        DateTimeOffset.UtcNow,
                        Array.Empty<CheckResult>(),
                        new NetworkSnapshot(
                            string.Empty, string.Empty, string.Empty, string.Empty,
                            string.Empty, string.Empty, string.Empty, string.Empty,
                            Array.Empty<string>(), Array.Empty<StunResult>(),
                            Array.Empty<string>(), false, new Dictionary<string, string>()),
                        Array.Empty<ProcessInfo>());
                    var report = await engine.RunSingleCheckAsync(baseline, targetId, config, cancellationToken);
                    var found = report.Checks.FirstOrDefault(c => string.Equals(c.Id, targetId, StringComparison.OrdinalIgnoreCase));
                    if (found is null)
                    {
                        ctx.Error.WriteLine($"未知检查项：{args[1]}");
                        return 1;
                    }

                    checks = new[] { found };
                    ctx.Out.WriteLine($"{found.Id}={found.Status.ToString().ToLowerInvariant()}:{found.Detail}");
                    exitCode = found.Blocking && found.Status is CheckStatus.Fail or CheckStatus.Unknown ? 1 : 0;
                    break;
                }
                case "status":
                {
                    var current = ctx.AccountManager.GetCurrentSlot();
                    ctx.Out.WriteLine($"current={(string.IsNullOrEmpty(current) ? "none" : current)}");
                    foreach (var slot in ctx.AccountManager.ListSlots())
                    {
                        ctx.Out.WriteLine($"slot.{slot.Slot}={slot.StatusText}");
                    }

                    break;
                }
                case "switch":
                {
                    if (args.Length < 2 || !AccountSlotManager.IsValidSlot(args[1]))
                    {
                        ctx.Error.WriteLine("用法: switch <A|B|C|D>");
                        return 1;
                    }

                    var state = ctx.StateStore.Load();
                    if (state.Blocked)
                    {
                        ctx.Error.WriteLine("FAIL:当前处于阻断锁定状态，请先修复环境并解除阻断");
                        return 1;
                    }

                    var engine = new GuardianCheckEngine(ctx.Probe, ctx.ProcessInspector);
                    var report = await engine.RunAsync(config, full: true, cancellationToken);
                    checks = report.Checks;
                    var gate = ProtectionPolicyEvaluator.EvaluateLaunchGate(report, state.Blocked, state.IgnoreWebRtc);
                    var launch = !args.Any(a => string.Equals(a, "--no-launch", StringComparison.OrdinalIgnoreCase));
                    var res = ctx.AccountManager.SwitchToSlot(args[1], gate.Allowed, gate.Reason, launchAfterSwitch: launch);
                    if (res.Success)
                    {
                        ctx.Out.WriteLine($"OK:{res.Message}");
                        exitCode = 0;
                    }
                    else
                    {
                        ctx.Error.WriteLine($"FAIL:{res.Message}");
                        exitCode = 1;
                    }

                    break;
                }
                case "get-client":
                {
                    ctx.Out.WriteLine(ProxyClientModes.Normalize(config.ProxyClientMode));
                    break;
                }
                case "set-client":
                {
                    if (args.Length != 2 || !ProxyClientModes.IsValid(args[1]))
                    {
                        ctx.Error.WriteLine($"不支持的代理客户端模式；可选：{string.Join(" | ", ProxyClientModes.All)}");
                        return 1;
                    }

                    var updated = ctx.ConfigStore.Save(config with { ProxyClientMode = ProxyClientModes.Normalize(args[1]) }, preserveExistingApiKeyIfEmpty: true);
                    ctx.Out.WriteLine($"OK:proxy_client_mode={updated.ProxyClientMode}");
                    break;
                }
                case "get-flclash-controller":
                {
                    ctx.Out.WriteLine(string.IsNullOrWhiteSpace(config.FlClashController) ? "auto" : config.FlClashController);
                    break;
                }
                case "set-flclash-controller":
                {
                    var raw = args.Length >= 2 ? args[1].Trim() : string.Empty;
                    var normalized = raw.Equals("auto", StringComparison.OrdinalIgnoreCase) ? string.Empty : raw;
                    var updated = ctx.ConfigStore.Save(config with { FlClashController = normalized }, preserveExistingApiKeyIfEmpty: true);
                    ctx.Out.WriteLine($"OK:flclash_controller={(string.IsNullOrWhiteSpace(updated.FlClashController) ? "auto" : updated.FlClashController)}");
                    break;
                }
                case "set-region":
                {
                    if (ctx.Probe is not WindowsEnvironmentProbe winProbe)
                    {
                        ctx.Error.WriteLine("FAIL:当前探测实现不支持地区自适应");
                        return 1;
                    }

                    var adapt = await winProbe.ProbeRegionForAdaptAsync(config, cancellationToken);
                    if (!adapt.Success)
                    {
                        ctx.Error.WriteLine($"FAIL:{adapt.Error}");
                        return 1;
                    }

                    ctx.ConfigStore.Save(
                        config with { ExpectedExitCountry = adapt.Country, ExpectedLocale = adapt.Locale },
                        preserveExistingApiKeyIfEmpty: true);
                    ctx.Out.WriteLine($"OK:region={adapt.Country} tz={adapt.IanaTimezone} win_tz={adapt.WindowsTimezone} locale={adapt.Locale} source={adapt.Source}");
                    break;
                }
                case "rules-status":
                {
                    var audit = await ctx.ClashInspector.InspectAsync(config, cancellationToken);
                    ctx.Out.WriteLine($"mode={audit.Mode}");
                    ctx.Out.WriteLine($"status={audit.Status}");
                    ctx.Out.WriteLine($"webrtc_policy={WebRtcPolicies.Normalize(config.WebRtcPolicy)}");
                    ctx.Out.WriteLine($"pinned={(audit.PinnedRulesLoaded == true ? "yes" : audit.PinnedRulesLoaded == false ? "no" : "unknown")}");
                    if (!string.IsNullOrWhiteSpace(audit.EndpointBaseUrl))
                    {
                        ctx.Out.WriteLine($"api=source={audit.EndpointSource} endpoint={audit.EndpointBaseUrl}");
                    }

                    ctx.Out.WriteLine($"detail={audit.Detail}");
                    foreach (var rule in audit.HeadRules)
                    {
                        ctx.Out.WriteLine(rule);
                    }

                    exitCode = string.Equals(audit.Status, "fail", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
                    break;
                }
                case "fingerprint":
                {
                    ctx.Out.WriteLine(FingerprintInspector.RunReport());
                    break;
                }
                case "cli-info":
                {
                    ctx.Out.WriteLine(CliInspector.RunReport());
                    break;
                }
                case "open-safe":
                {
                    if (args.Length < 2 || string.IsNullOrWhiteSpace(args[1]))
                    {
                        ctx.Error.WriteLine("用法: open-safe <http(s)://url>");
                        return 1;
                    }

                    var launched = SafeBrowserLauncher.Launch(args[1], config, null);
                    if (launched.Success)
                    {
                        ctx.Out.WriteLine($"OK:{launched.Message}");
                    }
                    else
                    {
                        ctx.Error.WriteLine($"FAIL:{launched.Message}");
                        exitCode = 1;
                    }

                    break;
                }
                case "snapshot-export":
                {
                    if (args.Length < 3)
                    {
                        ctx.Error.WriteLine("用法: snapshot-export <A|B|C|D> <destination.csnap>（密码经 stdin 传入）");
                        return 1;
                    }

                    var password = (await ctx.In.ReadLineAsync(cancellationToken)) ?? string.Empty;
                    var res = ctx.AccountManager.ExportEncryptedSnapshot(args[1], args[2], password);
                    if (res.Success)
                    {
                        ctx.Out.WriteLine($"OK:{res.Message}");
                    }
                    else
                    {
                        ctx.Error.WriteLine($"FAIL:{res.Message}");
                        exitCode = 1;
                    }

                    break;
                }
                case "snapshot-import":
                {
                    if (args.Length < 3)
                    {
                        ctx.Error.WriteLine("用法: snapshot-import <source.csnap> <A|B|C|D>（密码经 stdin 传入）");
                        return 1;
                    }

                    var password = (await ctx.In.ReadLineAsync(cancellationToken)) ?? string.Empty;
                    var res = ctx.AccountManager.ImportEncryptedSnapshot(args[1], args[2], password);
                    if (res.Success)
                    {
                        ctx.Out.WriteLine($"OK:{res.Message}");
                    }
                    else
                    {
                        ctx.Error.WriteLine($"FAIL:{res.Message}");
                        exitCode = 1;
                    }

                    break;
                }
                case "get-check-config":
                {
                    // Never echo IP reputation API key; report only whether configured
                    var payload = new Dictionary<string, object?>
                    {
                        ["proxyClientMode"] = ProxyClientModes.Normalize(config.ProxyClientMode),
                        ["webrtcPolicy"] = WebRtcPolicies.Normalize(config.WebRtcPolicy),
                        ["disabled"] = config.DisabledOptionalChecks ?? Array.Empty<string>(),
                        ["allowOptionalFailures"] = config.AllowOptionalFailures,
                        ["logging"] = config.LoggingEnabled,
                        ["wfpStrictEnabled"] = config.WfpStrictEnabled,
                        ["wfpAllowLoopback"] = config.WfpAllowLoopback,
                        ["ipReputation"] = config.IpReputation is null
                            ? null
                            : new
                            {
                                url = config.IpReputation.Url,
                                configured = !string.IsNullOrWhiteSpace(config.IpReputation.Url),
                                keyConfigured = !string.IsNullOrWhiteSpace(config.IpReputation.Key),
                                threshold = config.IpReputation.Threshold,
                                cacheDays = config.IpReputation.CacheDays
                            }
                    };
                    ctx.Out.WriteLine(JsonSerializer.Serialize(payload));
                    break;
                }
                case "set-check-config":
                {
                    if (args.Length < 2 || string.IsNullOrWhiteSpace(args[1]))
                    {
                        ctx.Error.WriteLine("用法: set-check-config '<json>'");
                        return 1;
                    }

                    var updated = ApplyCheckConfigPatch(config, args[1]);
                    ctx.ConfigStore.Save(updated, preserveExistingApiKeyIfEmpty: true);
                    ctx.Out.WriteLine("OK:检查设置已保存");
                    break;
                }
                case "export-diagnostics":
                {
                    if (args.Length < 2 || string.IsNullOrWhiteSpace(args[1]))
                    {
                        ctx.Error.WriteLine("用法: export-diagnostics <output.zip>");
                        return 1;
                    }

                    DiagnosticsExporter.ExportZip(args[1], config, ctx.StateStore.Load(), null, ctx.Logger);
                    ctx.Out.WriteLine($"OK:诊断包已导出至 {args[1]}");
                    break;
                }
                default:
                {
                    ctx.Error.WriteLine($"未知命令：{args[0]}");
                    WriteUsage(ctx.Error);
                    return 1;
                }
            }
        }
        catch (Exception ex)
        {
            ctx.Error.WriteLine($"FAIL:{ex.Message}");
            exitCode = 1;
        }
        finally
        {
            sw.Stop();
            ctx.Logger.LogAction(
                "cli-" + command,
                exitCode == 0 ? "ok" : "fail",
                sw.ElapsedMilliseconds,
                checks,
                config.LoggingEnabled);
        }

        return exitCode;
    }

    private static async Task<int> RunDiagnoseProxyAsync(
        string[] subArgs,
        GuardianCliContext ctx,
        CancellationToken cancellationToken)
    {
        string? explicitProxy = null;
        string? configPath = null;

        for (var i = 0; i < subArgs.Length; i++)
        {
            var arg = subArgs[i];
            if (string.Equals(arg, "--proxy", StringComparison.OrdinalIgnoreCase) && i + 1 < subArgs.Length)
            {
                explicitProxy = subArgs[++i];
            }
            else if (string.Equals(arg, "--config", StringComparison.OrdinalIgnoreCase) && i + 1 < subArgs.Length)
            {
                configPath = subArgs[++i];
            }
            else
            {
                var err = new ProxyDiagnosticsRunner.ProxyDiagnosticsReport(
                    1, "proxy_diagnostics", "configuration_error", string.Empty, 0, string.Empty, false,
                    Array.Empty<ProxyDiagnosticsRunner.TargetProbeResult>(),
                    $"不支持的参数：{arg}（用法：diagnose-proxy [--proxy <url> | --config <file.json>]）");
                ctx.Out.WriteLine(ProxyDiagnosticsRunner.FormatReportJson(err));
                return 2;
            }
        }

        var envProxy = ctx.GetEnvironmentVariable("CLAUDE_SWITCHER_PROXY_URL");
        var report = await ProxyDiagnosticsRunner.RunFromSourcesAsync(explicitProxy, configPath, envProxy, cancellationToken);
        ctx.Out.WriteLine(ProxyDiagnosticsRunner.FormatReportJson(report));
        return ProxyDiagnosticsRunner.GetExitCode(report);
    }

    private static GuardianConfig ApplyCheckConfigPatch(GuardianConfig current, string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("配置 JSON 必须是对象");
        }

        var root = doc.RootElement;
        var updated = current;

        if (root.TryGetProperty("disabled", out var disabledProp) && disabledProp.ValueKind == JsonValueKind.Array)
        {
            var list = disabledProp.EnumerateArray()
                .Where(el => el.ValueKind == JsonValueKind.String)
                .Select(el => el.GetString()!)
                .ToArray();
            updated = updated with { DisabledOptionalChecks = list };
        }

        if (root.TryGetProperty("allowOptionalFailures", out var allowProp) &&
            (allowProp.ValueKind == JsonValueKind.True || allowProp.ValueKind == JsonValueKind.False))
        {
            updated = updated with { AllowOptionalFailures = allowProp.GetBoolean() };
        }

        if (root.TryGetProperty("logging", out var logProp) &&
            (logProp.ValueKind == JsonValueKind.True || logProp.ValueKind == JsonValueKind.False))
        {
            updated = updated with { LoggingEnabled = logProp.GetBoolean() };
        }

        if (root.TryGetProperty("webrtcPolicy", out var policyProp) && policyProp.ValueKind == JsonValueKind.String)
        {
            updated = updated with { WebRtcPolicy = policyProp.GetString() ?? WebRtcPolicies.Proxy };
        }

        if (root.TryGetProperty("ipReputation", out var repProp))
        {
            if (repProp.ValueKind == JsonValueKind.Null)
            {
                updated = updated with { IpReputation = null };
            }
            else if (repProp.ValueKind == JsonValueKind.Object)
            {
                var url = repProp.TryGetProperty("url", out var u) && u.ValueKind == JsonValueKind.String
                    ? u.GetString() ?? string.Empty
                    : current.IpReputation?.Url ?? string.Empty;
                var key = repProp.TryGetProperty("key", out var k) && k.ValueKind == JsonValueKind.String
                    ? k.GetString() ?? string.Empty
                    : string.Empty;
                var threshold = repProp.TryGetProperty("threshold", out var t) && t.TryGetDouble(out var tv)
                    ? tv
                    : current.IpReputation?.Threshold ?? 25;
                var cacheDays = repProp.TryGetProperty("cacheDays", out var c) && c.TryGetInt32(out var cv)
                    ? cv
                    : current.IpReputation?.CacheDays ?? 7;
                updated = updated with { IpReputation = new IpReputationConfig(url, key, threshold, cacheDays) };
            }
        }

        return updated;
    }

    private static void WriteUsage(TextWriter writer)
    {
        var sb = new StringBuilder();
        sb.AppendLine("ClaudeDesktopGuardian.Cli 用法：");
        sb.AppendLine("  check | checkdetail | check-item <check-id>");
        sb.AppendLine("  status | switch <A|B|C|D> [--no-launch]");
        sb.AppendLine("  set-region | get-client | set-client <mode>");
        sb.AppendLine("  get-flclash-controller | set-flclash-controller <port|127.0.0.1:port|auto>");
        sb.AppendLine("  rules-status | fingerprint | cli-info | open-safe <http(s)://url>");
        sb.AppendLine("  diagnose-proxy [--proxy <url> | --config <file.json>]");
        sb.AppendLine("  snapshot-export <A|B|C|D> <file.csnap>   (密码经 stdin 传入)");
        sb.AppendLine("  snapshot-import <file.csnap> <A|B|C|D>   (密码经 stdin 传入)");
        sb.AppendLine("  get-check-config | set-check-config '<json>' | export-diagnostics <file.zip>");
        writer.Write(sb.ToString());
    }
}
