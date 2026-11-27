using System.Windows;

namespace ClaudeDesktopGuardian.App;

public partial class App : System.Windows.Application
{
    private const string SingleInstanceMutexName = @"Local\ClaudeDesktopGuardian.SingleInstance";
    private const string ActivateEventName = @"Local\ClaudeDesktopGuardian.ActivateWindow";

    private Mutex? _instanceMutex;
    private EventWaitHandle? _activateEvent;
    private CancellationTokenSource? _activateListenerCts;

    protected override void OnStartup(StartupEventArgs e)
    {
        _instanceMutex = new Mutex(initiallyOwned: true, name: SingleInstanceMutexName, out var createdNew);
        if (!createdNew)
        {
            try
            {
                using var signal = EventWaitHandle.OpenExisting(ActivateEventName);
                signal.Set();
            }
            catch
            {
            }

            Shutdown(0);
            return;
        }

        _activateEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ActivateEventName);
        _activateListenerCts = new CancellationTokenSource();
        StartActivateListener(_activateListenerCts.Token);

        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { _activateListenerCts?.Cancel(); } catch { }
        try { _activateEvent?.Set(); } catch { }
        _activateEvent?.Dispose();
        _activateListenerCts?.Dispose();
        if (_instanceMutex is not null)
        {
            try { _instanceMutex.ReleaseMutex(); } catch { }
            _instanceMutex.Dispose();
        }

        base.OnExit(e);
    }

    private void StartActivateListener(CancellationToken token)
    {
        var waitHandle = _activateEvent;
        if (waitHandle is null)
        {
            return;
        }

        _ = Task.Run(() =>
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    if (!waitHandle.WaitOne())
                    {
                        break;
                    }

                    if (token.IsCancellationRequested)
                    {
                        break;
                    }

                    Dispatcher.BeginInvoke(() =>
                    {
                        if (MainWindow is MainWindow main)
                        {
                            main.BringToFrontFromExternalSignal();
                        }
                    });
                }
                catch
                {
                    break;
                }
            }
        }, token);
    }
}
