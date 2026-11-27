using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Windows.Threading;
using ClaudeDesktopGuardian.Core;

internal static class UiResponsivenessTests
{
    internal static async Task RunAsync(ICollection<string> failures)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
            dispatcher.BeginInvoke(new Action(async () =>
            {
                try
                {
                    await CheckEngineAsync(dispatcher, failures);
                    await CheckClashPipeAsync(dispatcher, failures);
                    completion.TrySetResult();
                }
                catch (Exception exception)
                {
                    completion.TrySetException(exception);
                }
                finally
                {
                    dispatcher.BeginInvokeShutdown(DispatcherPriority.Background);
                }
            }));
            Dispatcher.Run();
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        await completion.Task.WaitAsync(TimeSpan.FromSeconds(15));
    }

    private static async Task CheckEngineAsync(Dispatcher dispatcher, ICollection<string> failures)
    {
        var config = new GuardianConfig(ExpectedExitIp: "203.0.113.10", ExpectedExitCountry: "US");
        var snapshot = await new ExtendedFakeProbe().CaptureNetworkAsync(
            config, Array.Empty<ProcessInfo>(), true, CancellationToken.None);
        foreach (var kind in new[] { "full", "light", "single" })
        {
            using var releaseProbe = new ManualResetEventSlim();
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var probe = new BlockingProbe(dispatcher, entered, releaseProbe, snapshot);
            var inspector = new ThreadRecordingInspector(dispatcher);
            var browser = new ThreadRecordingBrowser(dispatcher);
            var engine = new GuardianCheckEngine(probe, inspector, browser);
            var heartbeat = Task.Run(async () =>
            {
                await entered.Task;
                await dispatcher.InvokeAsync(() => releaseProbe.Set());
            });
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var previous = new GuardianReport(DateTimeOffset.UtcNow, Array.Empty<CheckResult>(),
                probe.Snapshot, Array.Empty<ProcessInfo>());
            var report = kind == "single"
                ? await engine.RunSingleCheckAsync(previous, GuardianCheckIds.WebRtc, config, timeout.Token)
                : await engine.RunAsync(config, full: kind == "full", timeout.Token);
            await heartbeat;
            if (inspector.RanOnUi || probe.RanOnUi || !probe.HeartbeatWhileProbing)
            {
                failures.Add($"{kind} 检查不得在界面线程枚举进程或执行网络探测，探测期间 Dispatcher 必须响应操作");
            }
            if (kind != "light" && (!browser.RanOnUi || report.Network.BrowserWebRtc is null))
            {
                failures.Add($"{kind} 检查的 WebView2 探测必须保留在界面线程");
            }
            if (kind == "single" && !probe.UsedSingleCheck)
            {
                failures.Add("单项复检必须只调用单项探测入口");
            }
        }
    }

    private static async Task CheckClashPipeAsync(Dispatcher dispatcher, ICollection<string> failures)
    {
        foreach (var kind in new[] { "enabled", "disabled", "timeout", "cancel" })
        {
            var pipeName = "guardian-ui-regression-" + Guid.NewGuid().ToString("N");
            using var serverLifetime = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var callerLifetime = new CancellationTokenSource();
            await using var pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            var heartbeat = false;
            var requestedConfigs = false;
            var server = Task.Run(async () =>
            {
                try
                {
                    await pipe.WaitForConnectionAsync(serverLifetime.Token);
                    using var reader = new StreamReader(pipe, Encoding.ASCII, leaveOpen: true);
                    requestedConfigs = (await reader.ReadLineAsync(serverLifetime.Token)) == "GET /configs HTTP/1.1";
                    while (!string.IsNullOrEmpty(await reader.ReadLineAsync(serverLifetime.Token))) { }
                    await dispatcher.InvokeAsync(() =>
                    {
                        heartbeat = true;
                        if (kind == "cancel")
                        {
                            callerLifetime.Cancel();
                        }
                    });
                    if (kind is "timeout" or "cancel")
                    {
                        await Task.Delay(Timeout.InfiniteTimeSpan, serverLifetime.Token);
                    }
                    else
                    {
                        var body = kind == "enabled" ? "{\"tun\":{\"enable\":true}}" : "{\"tun\":{\"enable\":false}}";
                        var response = Encoding.ASCII.GetBytes(
                            $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}");
                        await pipe.WriteAsync(response, serverLifetime.Token);
                        await pipe.FlushAsync(serverLifetime.Token);
                    }
                }
                catch (OperationCanceledException) when (serverLifetime.IsCancellationRequested)
                {
                }
            });
            var endpoint = new ClashEndpoint(@"\\.\pipe\" + pipeName, string.Empty, "test", pipeName);
            try
            {
                var enabled = await ClashInspector.TryQueryLiveClashVergeTunEnabledAsync(
                    new[] { endpoint }, callerLifetime.Token).WaitAsync(TimeSpan.FromSeconds(3));
                bool? expected = kind == "enabled" ? true : kind == "disabled" ? false : null;
                if (enabled != expected || kind == "cancel")
                {
                    failures.Add($"Clash TUN 管道 {kind} 应准确读取状态、超时回退且传播调用方取消");
                }
            }
            catch (OperationCanceledException) when (kind == "cancel" && callerLifetime.IsCancellationRequested)
            {
            }
            finally
            {
                serverLifetime.Cancel();
                await server;
            }
            if (!heartbeat || !requestedConfigs)
            {
                failures.Add($"Clash TUN 管道 {kind} 检测期间界面必须仍能处理操作，且只访问隔离测试管道 /configs");
            }
        }
    }

    private sealed class BlockingProbe(
        Dispatcher dispatcher,
        TaskCompletionSource entered,
        ManualResetEventSlim release,
        NetworkSnapshot snapshot) : IEnvironmentProbe, ISingleCheckProbe
    {
        internal NetworkSnapshot Snapshot { get; } = snapshot;
        internal bool RanOnUi { get; private set; }
        internal bool HeartbeatWhileProbing { get; private set; }
        internal bool UsedSingleCheck { get; private set; }

        public Task<NetworkSnapshot> CaptureNetworkAsync(GuardianConfig config,
            IReadOnlyList<ProcessInfo> protectedProcesses, bool full, CancellationToken cancellationToken)
        {
            RanOnUi = dispatcher.CheckAccess();
            entered.TrySetResult();
            HeartbeatWhileProbing = release.Wait(TimeSpan.FromSeconds(1), cancellationToken);
            return Task.FromResult(Snapshot);
        }

        public Task<NetworkSnapshot> CaptureSingleCheckAsync(NetworkSnapshot previous, string checkId,
            GuardianConfig config, IReadOnlyList<ProcessInfo> protectedProcesses, CancellationToken cancellationToken)
        {
            UsedSingleCheck = true;
            return CaptureNetworkAsync(config, protectedProcesses, true, cancellationToken);
        }
    }

    private sealed class ThreadRecordingInspector(Dispatcher dispatcher) : IProcessInspector
    {
        internal bool RanOnUi { get; private set; }

        public IReadOnlyList<ProcessInfo> FindClaudeProcessTree()
        {
            RanOnUi = dispatcher.CheckAccess();
            return Array.Empty<ProcessInfo>();
        }
    }

    private sealed class ThreadRecordingBrowser(Dispatcher dispatcher) : IWebRtcBrowserProbe
    {
        internal bool RanOnUi { get; private set; }

        public Task<WebRtcBrowserResult> ProbeAsync(IReadOnlyList<string> stunUrls, CancellationToken cancellationToken)
        {
            RanOnUi = dispatcher.CheckAccess();
            return Task.FromResult(new WebRtcBrowserResult(true, "ok", true, Array.Empty<WebRtcCandidate>(), "测试"));
        }
    }
}
