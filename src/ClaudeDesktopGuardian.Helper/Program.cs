using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace ClaudeDesktopGuardian.Helper;

internal static class Program
{
    private const string PipeName = "ClaudeDesktopGuardian";
    private const int MaxPipeInstances = 4;

    public static async Task<int> Main(string[] args)
    {
        var dispatcher = new HelperCommandDispatcher(new WindowsHelperSystemExecutor());

        if (args.Any(a => string.Equals(a, "--cleanup-all", StringComparison.OrdinalIgnoreCase)))
        {
            string? statePath = null;
            for (var i = 0; i < args.Length - 1; i++)
            {
                if (string.Equals(args[i], "--state-path", StringComparison.OrdinalIgnoreCase))
                {
                    statePath = args[i + 1];
                    break;
                }
            }

            return await dispatcher.RunCleanupAllAsync(statePath);
        }

        // Accept multiple concurrent pipe connections so read-only status polls never stall behind slow mutations
        while (true)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = CreatePipe();
                await pipe.WaitForConnectionAsync();
                var acceptedPipe = pipe;
                pipe = null;
                _ = Task.Run(() => HandleClientAsync(acceptedPipe, dispatcher));
            }
            catch (IOException)
            {
                pipe?.Dispose();
            }
            catch (ObjectDisposedException)
            {
                pipe?.Dispose();
            }
            catch
            {
                pipe?.Dispose();
                await Task.Delay(100);
            }
        }
    }

    private static async Task HandleClientAsync(
        NamedPipeServerStream pipe,
        HelperCommandDispatcher dispatcher)
    {
        using (pipe)
        {
            try
            {
                using var ioTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                using var reader = new StreamReader(
                    pipe,
                    Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: true,
                    bufferSize: 4096,
                    leaveOpen: true);
                await using var writer = new StreamWriter(
                    pipe,
                    new UTF8Encoding(false),
                    4096,
                    leaveOpen: true)
                {
                    AutoFlush = true
                };

                var line = await reader.ReadLineAsync(ioTimeout.Token);
                if (line is null)
                {
                    return;
                }

                var response = await dispatcher.HandleLineAsync(line);
                await writer.WriteLineAsync(JsonSerializer.Serialize(response).AsMemory(), ioTimeout.Token);
            }
            catch (IOException)
            {
            }
            catch (OperationCanceledException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
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
            MaxPipeInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            0,
            0,
            security,
            HandleInheritability.None,
            0);
    }
}
