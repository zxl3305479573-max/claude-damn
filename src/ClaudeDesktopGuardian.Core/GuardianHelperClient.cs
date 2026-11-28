using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace ClaudeDesktopGuardian.Core;

public static class GuardianHelperClient
{
    public static async Task<JsonElement> SendAsync(string command, CancellationToken cancellationToken,
        string adapterGuid = "", bool allowLoopback = false, string? timezoneId = null)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(command == "status" ? 4 : 15));
        using var pipe = new NamedPipeClientStream(".", "ClaudeDesktopGuardian", PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(timeout.Token);
        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, true);
        await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, true) { AutoFlush = true };
        await writer.WriteLineAsync(JsonSerializer.Serialize(new
        {
            token = new PipeTokenStore().GetOrCreate(), command, adapterGuid, allowLoopback, timezoneId
        }).AsMemory(), timeout.Token);
        var text = await reader.ReadLineAsync(timeout.Token);
        using var document = JsonDocument.Parse(text ?? throw new IOException("管理员助手没有返回结果"));
        return document.RootElement.Clone();
    }

    public static async Task<HelperStatusSnapshot?> QueryStatusAsync(string adapterGuid, bool allowLoopback,
        CancellationToken cancellationToken)
    {
        try
        {
            var response = await SendAsync("status", cancellationToken, adapterGuid, allowLoopback);
            if (!response.TryGetProperty("ok", out var ok) || !ok.GetBoolean()) return null;
            string Text(string name) => response.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString() ?? "" : "";
            bool? Flag(string name) => response.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False
                ? value.GetBoolean() : null;
            return new(true, Text("helperDetail"), Text("wfpState"), Text("wfpDetail"), Flag("firewallApiOk") == true,
                response.TryGetProperty("firewallActiveRuleCount", out var count) && count.TryGetInt32(out var number) ? number : 0,
                Text("firewallDetail"), Flag("firewallPolicyEffective"), Text("tcpOnlyState"), Text("tcpOnlyDetail"));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return null; }
    }
}
