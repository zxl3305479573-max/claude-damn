using System.IO;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using ClaudeDesktopGuardian.Core;

namespace ClaudeDesktopGuardian.App;

public sealed class WebRtcBrowserProbe : IWebRtcBrowserProbe, IDisposable
{
    private readonly WebView2 _webView;
    private readonly SemaphoreSlim _probeLock = new(1, 1);
    private TaskCompletionSource<WebRtcBrowserResult>? _pendingResult;
    private Task<CoreWebView2Environment>? _environmentTask;
    private string _initializationError = string.Empty;
    private string? _pendingRequestId;
    private bool _initialized;

    public WebRtcBrowserProbe(WebView2 webView)
    {
        _webView = webView;
        _webView.CoreWebView2InitializationCompleted += OnInitializationCompleted;
        _webView.NavigationCompleted += OnNavigationCompleted;
        _webView.WebMessageReceived += OnWebMessageReceived;
    }

    public async Task<WebRtcBrowserResult> ProbeAsync(
        IReadOnlyList<string> stunUrls,
        CancellationToken cancellationToken)
    {
        await _probeLock.WaitAsync(cancellationToken);
        try
        {
            if (!await EnsureInitializedAsync(cancellationToken))
            {
                return WebRtcBrowserResult.Unsupported(
                    string.IsNullOrWhiteSpace(_initializationError)
                        ? "WebView2 Runtime 不可用或初始化失败"
                        : $"WebView2 初始化失败：{_initializationError}");
            }

            var pagePath = Path.Combine(
                AppContext.BaseDirectory,
                "web",
                "webrtc",
                "index.html");
            if (!File.Exists(pagePath))
            {
                return WebRtcBrowserResult.Unsupported(
                    "发布目录缺少本地 WebRTC 检测页面");
            }

            var completion = new TaskCompletionSource<WebRtcBrowserResult>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var requestId = Guid.NewGuid().ToString("N");
            _pendingResult = completion;
            _pendingRequestId = requestId;
            var encodedUrls = Uri.EscapeDataString(
                JsonSerializer.Serialize(stunUrls));
            var pageUrl =
                $"{new Uri(pagePath).AbsoluteUri}" +
                $"?stunUrls={encodedUrls}&timeoutMs=4000&requestId={requestId}";
            _webView.Source = new Uri(pageUrl);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(7));
            try
            {
                return await completion.Task.WaitAsync(timeout.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return new WebRtcBrowserResult(
                    true,
                    "incomplete",
                    false,
                    Array.Empty<WebRtcCandidate>(),
                    "WebView2 未在限定时间内返回 ICE 结果",
                    "浏览器检测超时");
            }
            finally
            {
                _pendingResult = null;
                _pendingRequestId = null;
            }
        }
        finally
        {
            _probeLock.Release();
        }
    }

    public void Dispose()
    {
        _webView.WebMessageReceived -= OnWebMessageReceived;
        _webView.NavigationCompleted -= OnNavigationCompleted;
        _webView.CoreWebView2InitializationCompleted -= OnInitializationCompleted;
        _probeLock.Dispose();
        _webView.Dispose();
    }

    private async Task<bool> EnsureInitializedAsync(
        CancellationToken cancellationToken)
    {
        if (_initialized && _webView.CoreWebView2 is not null)
        {
            return true;
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var userDataFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ClaudeDesktopGuardian",
                "WebView2");
            Directory.CreateDirectory(userDataFolder);
            _environmentTask ??= CoreWebView2Environment.CreateAsync(
                browserExecutableFolder: null,
                userDataFolder: userDataFolder);
            var environment = await _environmentTask;
            await _webView.EnsureCoreWebView2Async(environment);
            cancellationToken.ThrowIfCancellationRequested();
            var coreWebView = _webView.CoreWebView2;
            _initialized = coreWebView is not null;
            if (coreWebView is not null)
            {
                coreWebView.Settings.IsWebMessageEnabled = true;
            }
            return _initialized;
        }
        catch (Exception exception)
        {
            _initializationError = $"{exception.GetType().Name}：{exception.Message}";
            return false;
        }
    }

    private async void OnNavigationCompleted(
        object? sender,
        CoreWebView2NavigationCompletedEventArgs args)
    {
        if (_pendingResult is null)
        {
            return;
        }

        if (!IsCurrentRequest())
        {
            return;
        }

        if (!args.IsSuccess)
        {
            _pendingResult.TrySetResult(new WebRtcBrowserResult(
                true,
                "error",
                false,
                Array.Empty<WebRtcCandidate>(),
                "WebView2 本地检测页面加载失败",
                $"导航错误代码 {args.WebErrorStatus}"));
            return;
        }

        try
        {
            await _webView.ExecuteScriptAsync(
                "window.guardianRunWebRtcProbe()");
        }
        catch (Exception exception)
        {
            _pendingResult.TrySetResult(new WebRtcBrowserResult(
                true,
                "error",
                false,
                Array.Empty<WebRtcCandidate>(),
                "WebView2 无法执行 WebRTC 检测脚本",
                exception.Message));
        }
    }

    private void OnWebMessageReceived(
        object? sender,
        CoreWebView2WebMessageReceivedEventArgs args)
    {
        if (_pendingResult is null)
        {
            return;
        }

        try
        {
            var json = args.TryGetWebMessageAsString();
            var message = JsonSerializer.Deserialize<WebRtcMessage>(
                json,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
            if (message is null ||
                !string.Equals(message.RequestId, _pendingRequestId, StringComparison.Ordinal))
            {
                return;
            }

            _pendingResult.TrySetResult(message.Result ?? new WebRtcBrowserResult(
                true,
                "error",
                false,
                Array.Empty<WebRtcCandidate>(),
                "WebView2 返回了空的 WebRTC 结果",
                "空消息"));
        }
        catch (Exception exception)
        {
            _pendingResult.TrySetResult(new WebRtcBrowserResult(
                true,
                "error",
                false,
                Array.Empty<WebRtcCandidate>(),
                "WebView2 返回的 WebRTC 结果无法解析",
                exception.Message));
        }
    }

    private void OnInitializationCompleted(
        object? sender,
        CoreWebView2InitializationCompletedEventArgs args)
    {
        _initialized = args.IsSuccess && _webView.CoreWebView2 is not null;
    }

    private bool IsCurrentRequest()
    {
        var requestId = _pendingRequestId;
        var source = _webView.CoreWebView2?.Source;
        return !string.IsNullOrWhiteSpace(requestId) &&
               !string.IsNullOrWhiteSpace(source) &&
               source.Contains($"requestId={requestId}", StringComparison.Ordinal);
    }

    private sealed record WebRtcMessage(
        string RequestId,
        WebRtcBrowserResult? Result);
}
