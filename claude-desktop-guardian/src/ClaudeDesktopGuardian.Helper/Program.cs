using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ClaudeDesktopGuardian.Core;

namespace ClaudeDesktopGuardian.Helper;

internal static class Program
{
    private const string PipeName = "ClaudeDesktopGuardian";
    private const string RulePrefix = "ClaudeDesktopGuardian.";

    public static async Task Main()
    {
        while (true)
        {
            try
            {
                using var pipe = CreatePipe();
                await pipe.WaitForConnectionAsync();
                using var reader = new StreamReader(
                    pipe,
                    Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: true,
                    bufferSize: 1024,
                    leaveOpen: true);
                await using var writer = new StreamWriter(
                    pipe,
                    new UTF8Encoding(false),
                    1024,
                    leaveOpen: true)
                {
                    AutoFlush = true
                };
                var line = await reader.ReadLineAsync();
                if (line is null)
                {
                    continue;
                }

                var response = await HandleAsync(line);
                await writer.WriteLineAsync(JsonSerializer.Serialize(response));
            }
            catch (IOException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }
    }

    private static async Task<object> HandleAsync(string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return new { ok = false, error = "空命令" };
        }

        try
        {
            var request = JsonSerializer.Deserialize<HelperRequest>(
                line,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (request is null ||
                request.Token != new PipeTokenStore().GetOrCreate() ||
                request.Command is not (
                    "status" or
                    "apply-block" or
                    "clear-block" or
                    "terminate-tree" or
                    "get-timezone" or
                    "apply-timezone" or
                    "restore-timezone"))
            {
                return new { ok = false, error = "未知命令" };
            }

            var sid = WindowsIdentity.GetCurrent().User?.Value ?? "unknown";
            var groupName = RulePrefix + sid.Replace('\\', '_');
            if (request.Command == "status")
            {
                return new
                {
                    ok = true,
                    command = request.Command,
                    group = groupName,
                    timezoneId = await ReadTimezoneAsync()
                };
            }

            var paths = request.Paths
                .OrEmpty()
                .Where(IsAllowedProgramPath)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (request.Command == "apply-block")
            {
                foreach (var path in paths)
                {
                    var ruleName = groupName + "." + HashPath(path);
                    await RunNetshAsync("advfirewall", "firewall", "add", "rule",
                        $"name={ruleName}", $"group={groupName}", "dir=out", "action=block", "enable=yes",
                        $"program={path}", "profile=any");
                }
            }
            else if (request.Command == "clear-block")
            {
                await ClearFirewallRulesAsync(groupName);
            }
            else if (request.Command == "terminate-tree")
            {
                foreach (var processId in request.ProcessIds.OrEmpty().Distinct())
                {
                    try
                    {
                        using var process = Process.GetProcessById(processId);
                        process.Kill(true);
                    }
                    catch
                    {
                    }
                }
            }
            else if (request.Command == "get-timezone")
            {
                return new
                {
                    ok = true,
                    command = request.Command,
                    timezoneId = await ReadTimezoneAsync()
                };
            }
            else if (request.Command is "apply-timezone" or "restore-timezone")
            {
                var timezoneId = request.TimezoneId?.Trim() ?? string.Empty;
                if (!WindowsTimezoneMapper.IsKnownWindowsId(timezoneId))
                {
                    return new { ok = false, error = "未知或不支持的 Windows 时区 ID" };
                }

                await SetTimezoneAsync(timezoneId);
                return new
                {
                    ok = true,
                    command = request.Command,
                    timezoneId = await ReadTimezoneAsync()
                };
            }

            return new { ok = true, command = request.Command, paths = paths.Length, group = groupName };
        }
        catch (Exception exception)
        {
            return new { ok = false, error = exception.GetType().Name + ": " + exception.Message };
        }
    }

    private static NamedPipeServerStream CreatePipe()
    {
        var security = new PipeSecurity();
        var currentUser = WindowsIdentity.GetCurrent().User;
        if (currentUser is not null)
        {
            security.AddAccessRule(new PipeAccessRule(
                currentUser,
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow));
        }

        return NamedPipeServerStreamAcl.Create(
            PipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            0,
            0,
            security,
            HandleInheritability.None,
            0);
    }

    private static string HashPath(string path)
    {
        var bytes = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(path));
        return Convert.ToHexString(bytes)[..16];
    }

    private static bool IsAllowedProgramPath(string path)
    {
        if (!Path.IsPathFullyQualified(path) ||
            !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(path))
        {
            return false;
        }

        var normalized = path.Replace('/', '\\');
        return normalized.Contains("\\AnthropicClaude\\", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("\\Programs\\Claude\\", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("\\Claude\\", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task RunNetshAsync(params string[] arguments)
    {
        await RunProcessAsync("netsh.exe", arguments);
    }

    private static async Task ClearFirewallRulesAsync(string groupName)
    {
        var escapedGroupName = EscapePowerShellString(groupName);
        var script = string.Join(
            Environment.NewLine,
            "$ErrorActionPreference = 'Stop'",
            $"$rules = @(Get-NetFirewallRule -Group '{escapedGroupName}' -ErrorAction SilentlyContinue)",
            "if ($rules.Count -gt 0) {",
            "    $rules | Remove-NetFirewallRule -ErrorAction Stop",
            "}",
            "Write-Output ('removed=' + $rules.Count)");
        await RunProcessAsync(
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));
    }

    private static string EscapePowerShellString(string value) =>
        value.Replace("'", "''", StringComparison.Ordinal);

    private static async Task<string> RunProcessAsync(
        string fileName,
        params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo);
        if (process is null)
        {
            throw new InvalidOperationException($"无法启动 {fileName}");
        }

        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        var output = await outputTask;
        var error = await errorTask;
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                ProcessDiagnostics.FormatFailure(fileName, process.ExitCode, output, error));
        }

        return output;
    }

    private static async Task<string> ReadTimezoneAsync()
    {
        return (await RunProcessAsync("tzutil.exe", "/g")).Trim();
    }

    private static Task SetTimezoneAsync(string timezoneId) =>
        RunProcessAsync("tzutil.exe", "/s", timezoneId);

    private sealed record HelperRequest(
        string Token,
        string Command,
        IReadOnlyList<string>? Paths,
        IReadOnlyList<int>? ProcessIds,
        string? TimezoneId);

}

file static class RequestExtensions
{
    public static IReadOnlyList<T> OrEmpty<T>(this IReadOnlyList<T>? values) =>
        values ?? Array.Empty<T>();
}

