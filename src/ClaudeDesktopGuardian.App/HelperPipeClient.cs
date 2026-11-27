using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using ClaudeDesktopGuardian.Core;

namespace ClaudeDesktopGuardian.App;

internal sealed record HelperCallResult(
    bool Success,
    string Detail,
    string? WfpState,
    string? WfpDetail = null,
    bool? FirewallApiOk = null,
    int? FirewallActiveRuleCount = null,
    string? FirewallDetail = null,
    string? HelperDetail = null,
    bool? FirewallPolicyEffective = null,
    string? TcpOnlyState = null,
    string? TcpOnlyDetail = null);

/// <summary>
/// Isolated named-pipe client for ClaudeDesktopGuardian.Helper with explicit connect/read/write
/// timeouts, automatic stale-token cache refresh retry, and shared-runtime + legacy path discovery.
/// </summary>
internal static class HelperPipeClient
{
    private const string PipeName = "ClaudeDesktopGuardian";
    private const int DefaultIoTimeoutMs = 12_000;
    private const int ConnectTimeoutMs = 3_000;

    public static async Task<HelperCallResult> SendAsync(
        string command,
        GuardianReport? report,
        string? timezoneId = null,
        string? adapterGuid = null,
        bool allowLoopback = false,
        IReadOnlyList<string>? adapterNames = null,
        int timeoutMs = DefaultIoTimeoutMs,
        CancellationToken cancellationToken = default)
    {
        var tokenStore = new PipeTokenStore();
        var result = await SendOnceAsync(
            tokenStore.GetOrCreate(),
            command,
            report,
            timezoneId,
            adapterGuid,
            allowLoopback,
            adapterNames,
            timeoutMs,
            cancellationToken);

        // If Helper rotated/recreated pipe.token on startup, invalidate in-memory cache and retry once
        if (!result.Success &&
            result.Detail.Contains("认证失败", StringComparison.Ordinal))
        {
            tokenStore.InvalidateCache();
            result = await SendOnceAsync(
                tokenStore.GetOrCreate(),
                command,
                report,
                timezoneId,
                adapterGuid,
                allowLoopback,
                adapterNames,
                timeoutMs,
                cancellationToken);
        }

        return result;
    }

    public static string? FindHelperPath()
    {
        var candidates = new[]
        {
            // Preferred shared-runtime single-directory layout
            Path.Combine(AppContext.BaseDirectory, "ClaudeDesktopGuardian.Helper.exe"),
            // Legacy subfolder layout
            Path.Combine(AppContext.BaseDirectory, "helper", "ClaudeDesktopGuardian.Helper.exe"),
            // Local build output layout
            Path.GetFullPath(Path.Combine(
                AppContext.BaseDirectory,
                "..",
                "helper-win-x64",
                "ClaudeDesktopGuardian.Helper.exe"))
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    public static async Task<(bool Ready, string Error)> EnsureStartedAsync(
        CancellationToken cancellationToken = default)
    {
        var status = await SendAsync("status", null, timeoutMs: 5_000, cancellationToken: cancellationToken);
        if (status.Success)
        {
            return (true, string.Empty);
        }

        var helperPath = FindHelperPath();
        if (string.IsNullOrWhiteSpace(helperPath))
        {
            return (false, "找不到管理员助手程序 ClaudeDesktopGuardian.Helper.exe");
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = helperPath,
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Path.GetDirectoryName(helperPath)
            });
        }
        catch (Exception exception)
        {
            return (false, $"管理员助手启动失败：{exception.Message}");
        }

        for (var attempt = 0; attempt < 12; attempt++)
        {
            await Task.Delay(300, cancellationToken);
            status = await SendAsync("status", null, timeoutMs: 5_000, cancellationToken: cancellationToken);
            if (status.Success)
            {
                return (true, string.Empty);
            }
        }

        return (false, $"管理员助手未响应：{status.Detail}");
    }

    private static async Task<HelperCallResult> SendOnceAsync(
        string token,
        string command,
        GuardianReport? report,
        string? timezoneId,
        string? adapterGuid,
        bool allowLoopback,
        IReadOnlyList<string>? adapterNames,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        try
        {
            using var ioTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            ioTimeout.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(2_000, timeoutMs)));

            using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using (var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(ioTimeout.Token))
            {
                connectTimeout.CancelAfter(ConnectTimeoutMs);
                await pipe.ConnectAsync(connectTimeout.Token);
            }

            using var writer = new StreamWriter(
                pipe,
                new UTF8Encoding(false),
                4096,
                leaveOpen: true)
            {
                AutoFlush = true
            };
            using var reader = new StreamReader(
                pipe,
                Encoding.UTF8,
                detectEncodingFromByteOrderMarks: true,
                bufferSize: 4096,
                leaveOpen: true);

            var request = new
            {
                token,
                command,
                paths = report?.ProtectedProcesses
                    .Select(process => process.Path)
                    .Where(path => !string.IsNullOrWhiteSpace(path))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray() ?? Array.Empty<string>(),
                processIds = report?.ProtectedProcesses
                    .Select(process => process.ProcessId)
                    .ToArray() ?? Array.Empty<int>(),
                timezoneId,
                adapterGuid,
                allowLoopback,
                adapterNames
            };

            var payload = JsonSerializer.Serialize(request);
            await writer.WriteLineAsync(payload.AsMemory(), ioTimeout.Token);
            var response = await reader.ReadLineAsync(ioTimeout.Token);
            if (string.IsNullOrWhiteSpace(response))
            {
                return new HelperCallResult(false, "管理员助手没有返回结果", null);
            }

            using var document = JsonDocument.Parse(response);
            var root = document.RootElement;
            var success = root.TryGetProperty("ok", out var ok) && ok.GetBoolean();
            var wfpState = root.TryGetProperty("wfpState", out var wfpProp) ? wfpProp.GetString() : null;
            var wfpDetail = root.TryGetProperty("wfpDetail", out var wfpDetProp) ? wfpDetProp.GetString() : null;
            bool? fwApiOk = root.TryGetProperty("firewallApiOk", out var fwOkProp) && fwOkProp.ValueKind is JsonValueKind.True or JsonValueKind.False
                ? fwOkProp.GetBoolean()
                : null;
            int? fwCount = root.TryGetProperty("firewallActiveRuleCount", out var fwCntProp) && fwCntProp.TryGetInt32(out var cnt)
                ? cnt
                : null;
            var fwDetail = root.TryGetProperty("firewallDetail", out var fwDetProp) ? fwDetProp.GetString() : null;
            var helperDetail = root.TryGetProperty("helperDetail", out var hDetProp) ? hDetProp.GetString() : null;
            bool? effective = root.TryGetProperty("firewallPolicyEffective", out var effectiveProp) &&
                effectiveProp.ValueKind is JsonValueKind.True or JsonValueKind.False ? effectiveProp.GetBoolean() : null;
            var tcpState = root.TryGetProperty("tcpOnlyState", out var tcpProp) ? tcpProp.GetString() : null;
            var tcpDetail = root.TryGetProperty("tcpOnlyDetail", out var tcpDetailProp) ? tcpDetailProp.GetString() : null;
            var detail = success
                ? root.TryGetProperty("detail", out var detProp) && !string.IsNullOrWhiteSpace(detProp.GetString())
                    ? detProp.GetString()!
                    : root.TryGetProperty("timezoneId", out var timezone)
                        ? timezone.GetString() ?? "管理员助手已确认"
                        : "管理员助手已确认"
                : root.TryGetProperty("error", out var error)
                    ? error.GetString() ?? "管理员助手拒绝命令"
                    : "管理员助手拒绝命令";

            return new HelperCallResult(success, detail, wfpState, wfpDetail, fwApiOk, fwCount, fwDetail, helperDetail,
                effective, tcpState, tcpDetail);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new HelperCallResult(false, $"管理员助手管道通信超时（>{timeoutMs} ms）", null);
        }
        catch (Exception exception)
        {
            return new HelperCallResult(false, exception.Message, null);
        }
    }
}
