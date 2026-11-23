using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Forms;
using ClaudeDesktopGuardian.Core;

namespace ClaudeDesktopGuardian.App;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<CheckResult> _checks = new();
    private readonly GuardianCheckEngine _engine;
    private readonly WebRtcBrowserProbe _browserProbe;
    private readonly WindowsClaudeProcessMonitor _processMonitor = new();
    private readonly GuardianConfig _config = new();
    private readonly GuardianStateStore _stateStore = new();
    private readonly System.Windows.Threading.DispatcherTimer _timer;
    private readonly NotifyIcon _trayIcon;
    private readonly ToolStripMenuItem _compactWindowMenuItem;
    private readonly SemaphoreSlim _checkGate = new(1, 1);
    private GuardianReport? _lastReport;
    private MiniStatusWindow? _compactWindow;
    private bool _blocked;
    private bool _ignoreWebRtc;
    private bool _compactWindowEnabled;
    private bool _allowExit;
    private bool _timezoneRecoveryReady;
    private string _timezoneOperationError = string.Empty;
    private DateTimeOffset _lastFullCheck = DateTimeOffset.MinValue;

    public MainWindow()
    {
        InitializeComponent();
        _browserProbe = new(WebRtcWebView);
        _engine = new(
            new WindowsEnvironmentProbe(),
            new WindowsProcessInspector(),
            _browserProbe);
        var state = _stateStore.Load();
        _blocked = state.Blocked;
        _ignoreWebRtc = state.IgnoreWebRtc;
        _compactWindowEnabled = state.CompactWindowEnabled;
        IgnoreWebRtcCheckBox.IsChecked = _ignoreWebRtc;
        if (_blocked)
        {
            TripReasonText.Text = string.IsNullOrWhiteSpace(state.TripReason)
                ? "上次运行留下阻断状态"
                : state.TripReason;
        }

        _trayIcon = new NotifyIcon
        {
            Icon = LoadTrayIcon(),
            Text = "Claude Desktop Guardian",
            Visible = true,
            ContextMenuStrip = new ContextMenuStrip()
        };
        _trayIcon.ContextMenuStrip.Items.Add("打开面板", null, (_, _) => ShowFromTray());
        _compactWindowMenuItem = new ToolStripMenuItem(
            "保留右下角小窗口",
            null,
            CompactWindowMenuItem_Click)
        {
            CheckOnClick = true,
            Checked = _compactWindowEnabled
        };
        _trayIcon.ContextMenuStrip.Items.Add(_compactWindowMenuItem);
        _trayIcon.ContextMenuStrip.Items.Add("退出并恢复时区", null, (_, _) => ExitFromTray());
        _trayIcon.DoubleClick += (_, _) => ShowFromTray();
        Closing += (_, args) =>
        {
            if (!_allowExit)
            {
                args.Cancel = true;
                Hide();
            }
        };
        Closed += (_, _) =>
        {
            _compactWindow?.Close();
            _processMonitor.Dispose();
            _checkGate.Dispose();
            _browserProbe.Dispose();
            _trayIcon.Dispose();
        };

        ChecksList.ItemsSource = _checks;
        _timer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(5)
        };
        _timer.Tick += async (_, _) =>
        {
            var full = DateTimeOffset.UtcNow - _lastFullCheck >=
                       TimeSpan.FromMinutes(_config.FullIntervalMinutes);
            await RunCheckAsync(full);
        };
        Loaded += async (_, _) =>
        {
            var helperReady = await EnsureHelperAvailableAsync();
            _processMonitor.Changed += ClaudeProcessMonitor_Changed;
            _processMonitor.TryStart();
            _timezoneRecoveryReady = helperReady && await RestoreStaleTimezoneAsync();
            _timer.Start();
            _lastFullCheck = DateTimeOffset.UtcNow;
            var report = await RunCheckAsync(true);
            if (_timezoneRecoveryReady && report is not null)
            {
                await EnsureExitTimezoneAsync(report);
            }

            if (_compactWindowEnabled)
            {
                ShowCompactWindow();
            }
        };
    }

    private void ClaudeProcessMonitor_Changed(object? sender, EventArgs e)
    {
        _ = Dispatcher.InvokeAsync(async () =>
        {
            await RunCheckAsync(false);
        });
    }

    private void ShowFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private static System.Drawing.Icon LoadTrayIcon()
    {
        var iconPath = Path.Combine(
            AppContext.BaseDirectory,
            "Assets",
            "claude-desktop-guardian.ico");
        return File.Exists(iconPath)
            ? new System.Drawing.Icon(iconPath)
            : System.Drawing.SystemIcons.Shield;
    }

    private void CompactWindowMenuItem_Click(object? sender, EventArgs e)
    {
        _compactWindowEnabled = _compactWindowMenuItem.Checked;
        var state = _stateStore.Load();
        _stateStore.Save(state with { CompactWindowEnabled = _compactWindowEnabled });

        if (_compactWindowEnabled)
        {
            ShowCompactWindow();
        }
        else
        {
            _compactWindow?.Close();
            _compactWindow = null;
        }
    }

    private void ShowCompactWindow()
    {
        if (_compactWindow is null)
        {
            _compactWindow = new MiniStatusWindow();
            _compactWindow.OpenRequested += ShowFromTray;
            _compactWindow.Closed += (_, _) => _compactWindow = null;
        }

        _compactWindow.UpdateStatus(
            ProtectionStateText.Text,
            ProtectionStateText.Foreground,
            ExitIpText.Text,
            AdapterText.Text,
            LastCheckText.Text);
        _compactWindow.Show();
        PositionCompactWindow();
    }

    private void PositionCompactWindow()
    {
        if (_compactWindow is null)
        {
            return;
        }

        var workArea = SystemParameters.WorkArea;
        _compactWindow.Left = Math.Max(
            workArea.Left + 8,
            workArea.Right - _compactWindow.Width - 16);
        _compactWindow.Top = Math.Max(
            workArea.Top + 8,
            workArea.Bottom - _compactWindow.Height - 16);
    }

    private async void ExitFromTray()
    {
        if (!await RestoreTimezoneAsync())
        {
            ShowFromTray();
            System.Windows.MessageBox.Show(
                $"时区恢复失败：{_timezoneOperationError}",
                "无法退出",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        _allowExit = true;
        _trayIcon.Visible = false;
        Close();
    }

    private async void CheckButton_Click(object sender, RoutedEventArgs e)
    {
        await RunCheckAsync(true);
    }

    private async void IgnoreWebRtcCheckBox_Click(object sender, RoutedEventArgs e)
    {
        _ignoreWebRtc = IgnoreWebRtcCheckBox.IsChecked == true;
        var state = _stateStore.Load();
        _stateStore.Save(state with { IgnoreWebRtc = _ignoreWebRtc });
        await RunCheckAsync(true);
    }

    private async void RecoverButton_Click(object sender, RoutedEventArgs e)
    {
        var report = await RunCheckAsync(true);
        if (report is null || GetEffectiveBlockingFailures(report).Count > 0)
        {
            return;
        }

        var helperResult = await SendHelperAsync("clear-block", report);
        if (!helperResult.Success)
        {
            System.Windows.MessageBox.Show(
                $"管理员助手没有确认解除阻断：{helperResult.Detail}",
                "恢复失败",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        _blocked = false;
        SaveGuardianState(false, string.Empty, null, report.ObservedAt);
        TripReasonText.Text = "暂无";
        SetProtectionState("已恢复", "StatusOkBackgroundBrush", "StatusOkBrush");
    }

    private async Task<GuardianReport?> RunCheckAsync(bool full)
    {
        await _checkGate.WaitAsync();
        try
        {
            return await RunCheckCoreAsync(full);
        }
        finally
        {
            _checkGate.Release();
        }
    }

    private async Task<GuardianReport?> RunCheckCoreAsync(bool full)
    {
        try
        {
            LastCheckText.Text = "正在检查网络、DNS、IPv6 和 Claude 进程…";
            if (full)
            {
                _lastFullCheck = DateTimeOffset.UtcNow;
            }
            var report = await _engine.RunAsync(_config, full, CancellationToken.None);
            _lastReport = report;
            Render(report);
            var blockingFailures = GetEffectiveBlockingFailures(report);
            var shouldBlock = blockingFailures.Count > 0 &&
                              report.ProtectedProcesses.Count > 0;
            if (shouldBlock && !_blocked)
            {
                var tripReason = FormatTripReason(blockingFailures);
                var helperResult = await SendHelperAsync("apply-block", report);
                if (helperResult.Success)
                {
                    _blocked = true;
                    TripReasonText.Text = tripReason;
                    SaveGuardianState(true, tripReason, DateTimeOffset.UtcNow, report.ObservedAt);
                    await SendHelperAsync("terminate-tree", report);
                    SetProtectionState("已阻断", "StatusWarnBackgroundBrush", "StatusWarnBrush");
                }
                else
                {
                    TripReasonText.Text = $"{tripReason}；阻断动作失败：{helperResult.Detail}";
                    SetProtectionState("阻断失败", "StatusErrorBackgroundBrush", "StatusErrorBrush");
                }
            }
            else if (!shouldBlock && _blocked)
            {
                var helperResult = await SendHelperAsync("clear-block", report);
                if (helperResult.Success)
                {
                    _blocked = false;
                    SaveGuardianState(false, string.Empty, null, report.ObservedAt);
                    TripReasonText.Text = _ignoreWebRtc && report.HasConfirmedWebRtcLeak
                        ? "已手动忽略 WebRTC 阻断，未断网；检测证据仍保留在面板"
                        : blockingFailures.Count == 0
                        ? "暂无"
                        : "当前阻断条件已解除，网络已恢复";
                    SetReportProtectionState(report);
                }
                else
                {
                    TripReasonText.Text = $"未确认泄露，但解除断网失败：{helperResult.Detail}";
                }
            }
            else
            {
                if (!_blocked)
                {
                    TripReasonText.Text = blockingFailures.Count == 0
                        ? "暂无"
                        : FormatTripReason(blockingFailures);
                    SetReportProtectionState(report);
                }

                SaveGuardianState(
                    _blocked,
                    TripReasonText.Text,
                    _blocked ? DateTimeOffset.UtcNow : null,
                    report.ObservedAt);
            }

            return report;
        }
        catch (Exception exception)
        {
            var detail = $"后台检查失败：{exception.Message}";
            if (!_blocked && _lastReport is { ProtectedProcesses.Count: > 0 } lastReport)
            {
                var helperResult = await SendHelperAsync("apply-block", lastReport);
                if (helperResult.Success)
                {
                    _blocked = true;
                    TripReasonText.Text = detail;
                    SaveGuardianState(true, detail, DateTimeOffset.UtcNow, lastReport.ObservedAt);
                    await SendHelperAsync("terminate-tree", lastReport);
                    SetProtectionState("已阻断", "StatusWarnBackgroundBrush", "StatusWarnBrush");
                    return null;
                }

                detail = $"{detail}；阻断动作失败：{helperResult.Detail}";
                SetProtectionState("阻断失败", "StatusErrorBackgroundBrush", "StatusErrorBrush");
            }
            else if (_blocked)
            {
                SetProtectionState("已阻断", "StatusWarnBackgroundBrush", "StatusWarnBrush");
            }
            else
            {
                SetProtectionState("检查错误", "StatusErrorBackgroundBrush", "StatusErrorBrush");
            }

            TripReasonText.Text = detail;
            return null;
        }
    }

    private IReadOnlyList<CheckResult> GetEffectiveBlockingFailures(GuardianReport report) =>
        report.BlockingFailures
            .Where(check =>
                check.Id != "webrtc" ||
                check.Status == CheckStatus.Fail)
            .Where(check => !(_ignoreWebRtc && check.Id == "webrtc"))
            .ToArray();

    private static string FormatTripReason(IReadOnlyList<CheckResult> failures) =>
        string.Join(
            "；",
            failures.Select(check =>
                $"{check.Title}（{check.Status}）：{check.Detail}"));

    private void Render(GuardianReport report)
    {
        _checks.Clear();
        foreach (var check in report.Checks)
        {
            _checks.Add(check);
        }

        var issues = GetEffectiveBlockingFailures(report)
            .Select(check => $"{check.Title}（{check.Status}）：{check.Detail}")
            .ToArray();
        if (_blocked && issues.Length > 0)
        {
            TripReasonText.Text = string.Join("；", issues);
        }
        else if (!_blocked)
        {
            TripReasonText.Text = "暂无";
        }

        AdapterText.Text = string.IsNullOrWhiteSpace(report.Network.AdapterName)
            ? "未识别"
            : report.Network.AdapterName;
        ExitIpText.Text = string.IsNullOrWhiteSpace(report.Network.ExitIp)
            ? string.IsNullOrWhiteSpace(report.Network.Ipv4ProbeDetail)
                ? "未取得"
                : $"未取得（{report.Network.Ipv4ProbeDetail}）"
            : $"{report.Network.ExitIp} / {report.Network.ExitCountry}";
        ExitIpv6Text.Text = string.IsNullOrWhiteSpace(report.Network.ExitIpv6)
            ? report.Network.HasIpv6
                ? $"IPv6 出口：未取得{FormatProbeDetail(report.Network.Ipv6ProbeDetail)}"
                : "IPv6 出口：未启用"
            : $"{report.Network.ExitIpv6} / {report.Network.ExitIpv6Country}";
        var ipv6HasNoPublicEgress = report.Network.Ipv6ProbeDetail.Contains(
            "返回的地址不是 IPv6",
            StringComparison.OrdinalIgnoreCase);
        ExitIpv6Text.Foreground = report.Network.HasIpv6 &&
                                  string.IsNullOrWhiteSpace(report.Network.ExitIpv6) &&
                                  !ipv6HasNoPublicEgress
            ? (System.Windows.Media.Brush)FindResource("StatusWarnBrush")
            : (System.Windows.Media.Brush)FindResource("MutedBrush");
        TimezoneText.Text = string.IsNullOrWhiteSpace(report.Network.ExitWindowsTimezone)
            ? "未取得出口时区"
            : $"{report.Network.ExitTimezone} → {report.Network.ExitWindowsTimezone}";
        TimezoneStatusText.Text = string.IsNullOrWhiteSpace(_timezoneOperationError)
            ? $"系统：{report.Network.CurrentWindowsTimezone}"
            : _timezoneOperationError;
        TimezoneStatusText.Foreground = string.IsNullOrWhiteSpace(_timezoneOperationError)
            ? (System.Windows.Media.Brush)FindResource("MutedBrush")
            : (System.Windows.Media.Brush)FindResource("StatusWarnBrush");
        DnsText.Text = report.Network.DnsServers.Count == 0
            ? "未取得"
            : string.Join(", ", report.Network.DnsServers);
        ProcessText.Text = report.ProtectedProcesses.Count.ToString();
        WebRtcText.Text = string.Join(
            Environment.NewLine,
            BuildWebRtcLines(report));
        IgnoreWebRtcCheckBox.ToolTip = _ignoreWebRtc
            ? "当前已忽略 WebRTC 阻断，检测结果仍显示在面板中。点击取消后，下一次确认泄露会恢复阻断。"
            : "WebRTC 未验证不会被当作泄露。只有发现非 VPN 出口的公网候选地址时才会触发阻断。";
        ConnectionsText.Text = report.Network.ActiveConnections.Count == 0
            ? "暂无已建立 TCP 连接"
            : string.Join(Environment.NewLine, report.Network.ActiveConnections);
        LastCheckText.Text = $"最近检查：{report.ObservedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss}";
        UpdateCompactWindow();

        if (_blocked)
        {
            SetProtectionState("已阻断", "StatusWarnBackgroundBrush", "StatusWarnBrush");
        }
        else
        {
            SetReportProtectionState(report);
        }
    }

    private void SetReportProtectionState(GuardianReport report)
    {
        if (_ignoreWebRtc && report.HasConfirmedWebRtcLeak)
        {
            SetProtectionState("已忽略", "StatusWarnBackgroundBrush", "StatusWarnBrush");
        }
        else if (HasEffectiveStatus(report, CheckStatus.Fail))
        {
            SetProtectionState("异常", "StatusErrorBackgroundBrush", "StatusErrorBrush");
        }
        else if (HasEffectiveStatus(report, CheckStatus.Warn))
        {
            SetProtectionState("注意", "StatusWarnBackgroundBrush", "StatusWarnBrush");
        }
        else if (HasEffectiveStatus(report, CheckStatus.Unknown))
        {
            SetProtectionState("未验证", "StatusUnknownBackgroundBrush", "StatusUnknownBrush");
        }
        else
        {
            SetProtectionState("正常", "StatusOkBackgroundBrush", "StatusOkBrush");
        }
    }

    private bool HasEffectiveStatus(GuardianReport report, CheckStatus status) =>
        report.Checks.Any(check =>
            check.Blocking &&
            check.Status == status &&
            !(_ignoreWebRtc && check.Id == "webrtc"));

    private static IEnumerable<string> BuildWebRtcLines(GuardianReport report)
    {
        if (report.Network.BrowserWebRtc is { } browser)
        {
            yield return
                $"浏览器 ICE  {browser.Status}  完成={browser.Complete}  {browser.Detail}";
            if (!string.IsNullOrWhiteSpace(browser.Error))
            {
                yield return $"浏览器错误  {browser.Error}";
            }

            if (browser.Errors is { Count: > 0 })
            {
                foreach (var error in browser.Errors)
                {
                    yield return
                        $"ICE 错误  {error.Url}  code={error.Code}  {error.Text}".TrimEnd();
                }
            }
            else
            {
                yield return "ICE 错误  未报告";
            }

            foreach (var candidate in browser.Candidates)
            {
                yield return
                    $"候选地址  {candidate.Address}  {candidate.Kind}/{candidate.AddressFamily}";
            }
        }
        else
        {
            yield return "浏览器 ICE  未执行";
        }

        yield return "原生 STUN";
        foreach (var result in report.Network.StunResults)
        {
            yield return
                $"{result.Server}:{result.Port}  {result.Status}  {result.Address}  {result.Detail}";
        }
    }

    private void SetProtectionState(string text, string backgroundResource, string foregroundResource)
    {
        ProtectionStateText.Text = text;
        ProtectionStateBorder.Background = (System.Windows.Media.Brush)FindResource(backgroundResource);
        ProtectionStateText.Foreground = (System.Windows.Media.Brush)FindResource(foregroundResource);
        UpdateCompactWindow();
    }

    private void UpdateCompactWindow()
    {
        if (_compactWindow is null)
        {
            return;
        }

        _compactWindow.UpdateStatus(
            ProtectionStateText.Text,
            ProtectionStateText.Foreground,
            ExitIpText.Text,
            AdapterText.Text,
            LastCheckText.Text);
    }

    private async Task<bool> RestoreStaleTimezoneAsync()
    {
        var state = _stateStore.Load();
        if (!state.TimezoneOverrideActive ||
            string.IsNullOrWhiteSpace(state.OriginalWindowsTimezone))
        {
            return true;
        }

        var result = await SendHelperAsync(
            "restore-timezone",
            null,
            state.OriginalWindowsTimezone);
        if (!result.Success)
        {
            _timezoneOperationError = $"上次时区未恢复：{result.Detail}";
            return false;
        }

        _stateStore.Save(state with
        {
            TimezoneOverrideActive = false,
            OriginalWindowsTimezone = null,
            AppliedWindowsTimezone = null,
            TimezoneOverrideAt = null
        });
        return true;
    }

    private async Task<bool> EnsureHelperAvailableAsync()
    {
        var status = await SendHelperAsync("status", null);
        if (status.Success)
        {
            return true;
        }

        var helperPath = FindHelperPath();
        if (helperPath is null)
        {
            _timezoneOperationError = "管理员助手未运行，且未找到可启动的管理员助手程序";
            return false;
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
            _timezoneOperationError = $"管理员助手启动失败：{exception.Message}";
            return false;
        }

        for (var attempt = 0; attempt < 10; attempt++)
        {
            await Task.Delay(300);
            status = await SendHelperAsync("status", null);
            if (status.Success)
            {
                return true;
            }
        }

        _timezoneOperationError = $"管理员助手未响应：{status.Detail}";
        return false;
    }

    private static string? FindHelperPath()
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "helper", "ClaudeDesktopGuardian.Helper.exe"),
            Path.GetFullPath(Path.Combine(
                AppContext.BaseDirectory,
                "..",
                "helper-win-x64",
                "ClaudeDesktopGuardian.Helper.exe"))
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    private async Task EnsureExitTimezoneAsync(GuardianReport report)
    {
        var target = report.Network.ExitWindowsTimezone;
        if (string.IsNullOrWhiteSpace(target))
        {
            _timezoneOperationError = "无法取得出口 IP 对应的 Windows 时区，未修改系统时区";
            Render(report);
            return;
        }

        var current = report.Network.CurrentWindowsTimezone;
        if (string.IsNullOrWhiteSpace(current))
        {
            _timezoneOperationError = "无法读取当前 Windows 时区，未修改系统时区";
            Render(report);
            return;
        }

        if (string.Equals(current, target, StringComparison.OrdinalIgnoreCase))
        {
            _timezoneOperationError = string.Empty;
            TimezoneStatusText.Text = $"已匹配：{current}";
            return;
        }

        var state = _stateStore.Load();
        if (!state.TimezoneOverrideActive)
        {
            state = state with
            {
                TimezoneOverrideActive = true,
                OriginalWindowsTimezone = current,
                AppliedWindowsTimezone = target,
                TimezoneOverrideAt = DateTimeOffset.UtcNow
            };
            _stateStore.Save(state);
        }

        var result = await SendHelperAsync("apply-timezone", report, target);
        if (!result.Success)
        {
            _timezoneOperationError = $"系统时区修改失败：{result.Detail}";
            _stateStore.Save(state with
            {
                TimezoneOverrideActive = false,
                OriginalWindowsTimezone = null,
                AppliedWindowsTimezone = null,
                TimezoneOverrideAt = null
            });
            Render(report);
            return;
        }

        _timezoneOperationError = string.Empty;
        TimezoneStatusText.Text = $"已临时切换：{target}，退出时恢复 {current}";
        ApplyTimezoneResultToReport(report, target);
    }

    private void ApplyTimezoneResultToReport(GuardianReport report, string target)
    {
        var checks = report.Checks
            .Select(check => check.Id == "timezone"
                ? check with
                {
                    Status = CheckStatus.Ok,
                    Detail = $"系统时区 {target}，出口时区 {report.Network.ExitTimezone}"
                }
                : check)
            .ToArray();
        var updatedReport = report with
        {
            Checks = checks,
            Network = report.Network with
            {
                CurrentWindowsTimezone = target
            }
        };
        _lastReport = updatedReport;
        Render(updatedReport);
        SaveGuardianState(
            _blocked,
            TripReasonText.Text,
            _blocked ? DateTimeOffset.UtcNow : null,
            updatedReport.ObservedAt);
    }

    private async Task<bool> RestoreTimezoneAsync()
    {
        var state = _stateStore.Load();
        if (!state.TimezoneOverrideActive ||
            string.IsNullOrWhiteSpace(state.OriginalWindowsTimezone))
        {
            _timezoneOperationError = string.Empty;
            return true;
        }

        var result = await SendHelperAsync(
            "restore-timezone",
            null,
            state.OriginalWindowsTimezone);
        if (!result.Success)
        {
            _timezoneOperationError = result.Detail;
            return false;
        }

        _stateStore.Save(state with
        {
            TimezoneOverrideActive = false,
            OriginalWindowsTimezone = null,
            AppliedWindowsTimezone = null,
            TimezoneOverrideAt = null
        });
        _timezoneOperationError = string.Empty;
        return true;
    }

    private void SaveGuardianState(
        bool blocked,
        string tripReason,
        DateTimeOffset? blockedAt,
        DateTimeOffset? lastCheckedAt)
    {
        var state = _stateStore.Load();
        _stateStore.Save(state with
        {
            Blocked = blocked,
            TripReason = tripReason,
            BlockedAt = blockedAt,
            LastCheckedAt = lastCheckedAt
        });
    }

    private static async Task<HelperCallResult> SendHelperAsync(
        string command,
        GuardianReport? report,
        string? timezoneId = null)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", "ClaudeDesktopGuardian", PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(1200);
            using var writer = new StreamWriter(
                pipe,
                new UTF8Encoding(false),
                1024,
                leaveOpen: true)
            {
                AutoFlush = true
            };
            using var reader = new StreamReader(
                pipe,
                Encoding.UTF8,
                detectEncodingFromByteOrderMarks: true,
                bufferSize: 1024,
                leaveOpen: true);
            var request = new
            {
                token = new PipeTokenStore().GetOrCreate(),
                command,
                paths = report?.ProtectedProcesses
                    .Select(process => process.Path)
                    .Where(path => !string.IsNullOrWhiteSpace(path))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray() ?? Array.Empty<string>(),
                processIds = report?.ProtectedProcesses
                    .Select(process => process.ProcessId)
                    .ToArray() ?? Array.Empty<int>(),
                timezoneId
            };
            await writer.WriteLineAsync(JsonSerializer.Serialize(request));
            var response = await reader.ReadLineAsync();
            if (string.IsNullOrWhiteSpace(response))
            {
                return new HelperCallResult(false, "管理员助手没有返回结果");
            }

            using var document = JsonDocument.Parse(response);
            var root = document.RootElement;
            var success = root.TryGetProperty("ok", out var ok) && ok.GetBoolean();
            var detail = success
                ? root.TryGetProperty("timezoneId", out var timezone)
                    ? timezone.GetString() ?? "管理员助手已确认"
                    : "管理员助手已确认"
                : root.TryGetProperty("error", out var error)
                    ? error.GetString() ?? "管理员助手拒绝命令"
                    : "管理员助手拒绝命令";
            return new HelperCallResult(success, detail);
        }
        catch (Exception exception)
        {
            return new HelperCallResult(false, exception.Message);
        }
    }

    private static string FormatProbeDetail(string detail) =>
        string.IsNullOrWhiteSpace(detail) ? string.Empty : $"（{detail}）";

    private sealed record HelperCallResult(bool Success, string Detail);
}

