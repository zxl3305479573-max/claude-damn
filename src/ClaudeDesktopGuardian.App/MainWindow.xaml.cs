using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Forms;
using ClaudeDesktopGuardian.Core;
using WpfBrush = System.Windows.Media.Brush;
using WpfButton = System.Windows.Controls.Button;
using WpfCheckBox = System.Windows.Controls.CheckBox;
using WpfMessageBox = System.Windows.MessageBox;

namespace ClaudeDesktopGuardian.App;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<CheckResult> _checks = new();
    private readonly WindowsEnvironmentProbe _environmentProbe;
    private readonly GuardianCheckEngine _engine;
    private readonly WebRtcBrowserProbe _browserProbe;
    private readonly WindowsClaudeProcessMonitor _processMonitor = new();
    private readonly GuardianConfigStore _configStore = new();
    private readonly GuardianStateStore _stateStore = new();
    private readonly GuardianLogger _logger = new();
    private readonly AccountSlotManager _accountManager = new();
    private readonly ClashInspector _clashInspector = new();
    private readonly GuardianUpdateService _updateService = new();
    private readonly TaskCompletionSource<bool> _closedSignal = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Dictionary<string, WpfCheckBox> _optionalCheckBoxes = new(StringComparer.OrdinalIgnoreCase);
    private readonly System.Windows.Threading.DispatcherTimer _timer;
    private readonly NotifyIcon _trayIcon;
    private readonly ToolStripMenuItem _compactWindowMenuItem;
    private readonly SemaphoreSlim _checkGate = new(1, 1);
    private CancellationTokenSource _checkCancellation = new();

    private GuardianConfig _config;
    private GuardianReport? _lastReport;
    private MiniStatusWindow? _compactWindow;
    private bool _blocked;
    private bool _ignoreWebRtc;
    private bool _compactWindowEnabled;
    private bool _allowExit;
    private bool _exiting;
    private bool _operationInProgress;
    private bool _timezoneRecoveryReady;
    private bool _updateCheckInProgress;
    private bool _updateInstallInProgress;
    private string _timezoneOperationError = string.Empty;
    private string? _selectedCheckId;
    private DateTimeOffset _lastFullCheck = DateTimeOffset.MinValue;
    private bool _fullCheckPending = true;
    private GuardianUpdate? _availableUpdate;

    public MainWindow()
    {
        InitializeComponent();

        _config = _configStore.Load();
        _browserProbe = new WebRtcBrowserProbe(WebRtcWebView);
        _environmentProbe = new WindowsEnvironmentProbe(helperStatusProvider: QueryHelperStatusAsync);
        _engine = new GuardianCheckEngine(
            _environmentProbe,
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

        InitializeSettingsUi();
        LoadConfigToUi(_config);
        RefreshAccountUi();
        KeepPathsTextBox.Text = _accountManager.ReadKeepPathsText();

        _trayIcon = new NotifyIcon
        {
            Icon = LoadTrayIcon(),
            Text = "claude-damn",
            Visible = true,
            ContextMenuStrip = new ContextMenuStrip()
        };
        _trayIcon.ContextMenuStrip.Items.Add("打开面板", null, (_, _) => ShowFromTray());
        _trayIcon.ContextMenuStrip.Items.Add("安全启动 Claude", null, (_, _) => _ = LaunchClaudeSafeAsync());
        _compactWindowMenuItem = new ToolStripMenuItem(
            "保留右下角小窗口",
            null,
            CompactWindowMenuItem_Click)
        {
            CheckOnClick = true,
            Checked = _compactWindowEnabled
        };
        _trayIcon.ContextMenuStrip.Items.Add(_compactWindowMenuItem);
        _trayIcon.ContextMenuStrip.Items.Add("退出并恢复时区与网络策略", null, (_, _) => ExitFromTray());
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
            _closedSignal.TrySetResult(true);
            _timer?.Stop();
            _compactWindow?.Close();
            _processMonitor.Dispose();
            _checkGate.Dispose();
            _checkCancellation.Dispose();
            _browserProbe.Dispose();
            _trayIcon.Dispose();
        };

        ChecksList.ItemsSource = _checks;
        _timer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(_config.LightIntervalSeconds)
        };
        _timer.Tick += async (_, _) =>
        {
            if (_exiting || _checkGate.CurrentCount == 0)
            {
                return;
            }

            var full = _fullCheckPending || DateTimeOffset.UtcNow - _lastFullCheck >=
                       TimeSpan.FromMinutes(_config.FullIntervalMinutes);
            await RunCheckAsync(full);
        };
        Loaded += async (_, _) =>
        {
            var helperReady = await EnsureHelperAvailableAsync();
            if (_exiting || _allowExit)
            {
                return;
            }

            _processMonitor.Changed += ClaudeProcessMonitor_Changed;
            _processMonitor.TryStart();
            _timezoneRecoveryReady = helperReady && await RestoreStaleTimezoneAsync();
            if (helperReady) await ApplySavedTcpOnlyAsync();
            if (_exiting || _allowExit)
            {
                return;
            }

            _timer.Start();
            await RunCheckAsync(true);

            if (_compactWindowEnabled && !_exiting && !_allowExit)
            {
                ShowCompactWindow();
            }

            if (!_exiting && !_allowExit)
            {
                _ = CheckForUpdatesAsync(false);
            }
        };
    }

    private bool TryBeginOperation(string statusHint)
    {
        if (_operationInProgress || _exiting || _allowExit)
        {
            return false;
        }

        _operationInProgress = true;
        SetOperationControlsEnabled(false);
        if (!string.IsNullOrWhiteSpace(statusHint))
        {
            LastCheckText.Text = statusHint;
        }

        return true;
    }

    private void EndOperation()
    {
        _operationInProgress = false;
        SetOperationControlsEnabled(true);
    }

    private void SetOperationControlsEnabled(bool enabled)
    {
        var buttons = new WpfButton[]
        {
            CheckButton,
            UpdateButton,
            RecoverButton,
            BtnEnableWfpQuick,
            BtnDisableWfpQuick,
            BtnReconnectHelperQuick,
            BtnRefreshAccounts,
            BtnSwitchA,
            BtnSwitchB,
            BtnSwitchC,
            BtnSwitchD,
            BtnExportSnapshot,
            BtnImportSnapshot,
            BtnSaveKeepPaths,
            BtnOneClickFix,
            BtnReconnectHelperTool,
            BtnAdaptRegion,
            BtnEnableWfpTool,
            BtnDisableWfpTool,
            BtnSyncLocale,
            BtnClashStatus,
            BtnWriteClashRules,
            BtnFingerprint,
            BtnCliInfo,
            BtnExportDiagnostics,
            BtnOpenSafeBrowser,
            BtnPickProxyConfig,
            BtnDiagnoseProxy,
            BtnDetectProxyGroup,
            BtnResetSettings,
            BtnSaveSettings,
            BtnLaunchClaude
        };
        foreach (var btn in buttons)
        {
            btn.IsEnabled = enabled;
        }

        IgnoreWebRtcCheckBox.IsEnabled = enabled;
    }

    private void ClaudeProcessMonitor_Changed(object? sender, EventArgs e)
    {
        _ = Dispatcher.InvokeAsync(async () =>
        {
            await RunCheckAsync(false);
        });
    }

    public void BringToFrontFromExternalSignal()
    {
        ShowFromTray();
        Topmost = true;
        Topmost = false;
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
            LastCheckText.Text,
            WfpBadgeText.Text,
            AccountSubText.Text);
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
        if (_exiting || _allowExit)
        {
            return;
        }

        if (_operationInProgress)
        {
            ShowFromTray();
            WpfMessageBox.Show(
                "当前正在执行账号切换、修复或策略更新，请等待当前操作完成后再退出。",
                "暂不可退出",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        _exiting = true;
        _timer.Stop();
        _checkCancellation.Cancel();
        LastCheckText.Text = "正在停止检查并恢复时区与网络策略…";
        await _checkGate.WaitAsync();
        try
        {
            if (!await RestoreTimezoneAsync())
            {
                ShowFromTray();
                WpfMessageBox.Show(
                    $"时区恢复失败：{_timezoneOperationError}",
                    "无法退出",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            var clearRes = await SendHelperAsync("clear-block", _lastReport);
            if (clearRes.Success)
            {
                SaveGuardianState(false, string.Empty, null, _lastReport?.ObservedAt);
                _blocked = false;
            }

            await SendHelperAsync("wfp-disable", null);
            if (_config.TcpOnlyEnabled || _lastReport?.Network.TcpOnlyState is "active" or "stale" or "invalid")
            {
                var tcpOnly = await SendHelperAsync("tcp-only-disable", null);
                if (!tcpOnly.Success)
                    throw new InvalidOperationException("TCP-only 托管规则清理失败：" + tcpOnly.Detail);
            }

            _allowExit = true;
        }
        catch (Exception ex)
        {
            ShowFromTray();
            WpfMessageBox.Show($"退出恢复时发生错误：{ex.Message}", "退出失败", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            _checkGate.Release();
            if (!_allowExit)
            {
                _checkCancellation.Dispose();
                _checkCancellation = new CancellationTokenSource();
                _exiting = false;
                _timer.Start();
            }
        }

        if (_allowExit)
        {
            _trayIcon.Visible = false;
            Close();
        }
    }

    private void ChecksList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ChecksList.SelectedItem is CheckResult selected)
        {
            _selectedCheckId = selected.Id;
            SelectedEvidenceHeaderText.Text = $"选中项：{selected.Title} ({selected.Id})";
            SelectedEvidenceText.Text = UiPresentationState.FormatCheckEvidence(selected);
        }
    }

    private void CopyEvidenceButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var text = SelectedEvidenceText.Text;
            if (!string.IsNullOrWhiteSpace(text))
            {
                System.Windows.Clipboard.SetText(text);
                LastCheckText.Text = $"已复制选中项 Evidence 到剪贴板（{DateTime.Now:HH:mm:ss}）";
            }
        }
        catch (Exception ex)
        {
            LastCheckText.Text = $"复制剪贴板失败：{ex.Message}";
        }
    }

    private async void CheckButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBeginOperation("正在执行完整环境检查…"))
        {
            return;
        }

        try
        {
            await RunCheckAsync(true);
        }
        finally
        {
            EndOperation();
        }
    }

    private async void RetestCheckButton_Click(object sender, RoutedEventArgs e)
    {
        if (_operationInProgress || sender is not WpfButton { Tag: string checkId } || string.IsNullOrWhiteSpace(checkId))
        {
            return;
        }

        if (!await EnterCheckAsync())
        {
            return;
        }

        var sw = Stopwatch.StartNew();
        try
        {
            LastCheckText.Text = $"正在单项复检 {checkId}…";
            using var retestTimeout = CancellationTokenSource.CreateLinkedTokenSource(_checkCancellation.Token);
            retestTimeout.CancelAfter(TimeSpan.FromSeconds(25));
            var report = _lastReport is null
                ? await _engine.RunAsync(_config, full: true, retestTimeout.Token)
                : await _engine.RunSingleCheckAsync(_lastReport, checkId, _config, retestTimeout.Token);
            retestTimeout.Token.ThrowIfCancellationRequested();
            _lastReport = report;
            _selectedCheckId = checkId;
            Render(report);
            await ApplyProtectionDecisionAsync(report, allowClearBlock: false);
            sw.Stop();
            var single = report.Checks.FirstOrDefault(c => string.Equals(c.Id, checkId, StringComparison.OrdinalIgnoreCase));
            _logger.LogAction(
                "retest-" + checkId,
                single?.Status.ToString().ToLowerInvariant() ?? "ok",
                sw.ElapsedMilliseconds,
                report.Checks,
                _config.LoggingEnabled);
        }
        catch (OperationCanceledException) when (_exiting)
        {
        }
        catch (Exception ex)
        {
            TripReasonText.Text = $"单项复检失败：{ex.Message}";
            _fullCheckPending = true;
            if (_lastReport is not null)
            {
                _lastReport = EvidenceFreshness.AfterFailedCheck(_lastReport, sw.ElapsedMilliseconds, ex is OperationCanceledException);
                Render(_lastReport);
                await ApplyProtectionDecisionAsync(_lastReport, allowClearBlock: false);
            }
        }
        finally
        {
            _checkGate.Release();
        }
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
        if (!TryBeginOperation("正在执行完整检查以确认解除阻断…"))
        {
            return;
        }

        try
        {
            var report = await RunCheckAsync(true);
            if (report is null)
            {
                return;
            }

            var decision = ProtectionPolicyEvaluator.Evaluate(report, _blocked, _ignoreWebRtc, allowClearBlock: true);
            if (decision.BlockingFailures.Count > 0)
            {
                TripReasonText.Text = decision.TripReason;
                WpfMessageBox.Show(
                    $"仍有阻断项未通过，保持阻断状态：\n{decision.TripReason}",
                    "暂不可解除阻断",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            var helperResult = await SendHelperAsync("clear-block", report);
            if (!helperResult.Success)
            {
                TripReasonText.Text = $"解除阻断失败：{helperResult.Detail}";
                WpfMessageBox.Show(
                    $"无法解除防火墙阻断：{helperResult.Detail}",
                    "恢复失败",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            _blocked = false;
            SaveGuardianState(false, string.Empty, null, report.ObservedAt);
            TripReasonText.Text = "暂无";
            SetProtectionState("已恢复", "StatusOkBackgroundBrush", "StatusOkBrush");
            _logger.LogAction("recover", "ok", 0, report.Checks, _config.LoggingEnabled);
            await RunCheckAsync(false);
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task<GuardianReport?> RunCheckAsync(bool full)
    {
        if (!await EnterCheckAsync())
        {
            return null;
        }

        try
        {
            return await RunCheckCoreAsync(full);
        }
        finally
        {
            _checkGate.Release();
        }
    }

    private async Task<bool> EnterCheckAsync()
    {
        if (_exiting || _allowExit)
        {
            return false;
        }

        try
        {
            await _checkGate.WaitAsync(_checkCancellation.Token);
        }
        catch (OperationCanceledException)
        {
            return false;
        }

        if (_exiting || _allowExit)
        {
            _checkGate.Release();
            return false;
        }

        return true;
    }

    private async Task<GuardianReport?> RunCheckCoreAsync(bool full)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            LastCheckText.Text = full
                ? "正在执行完整检查（VPN / WFP / DNS / IPv6 / WebRTC / Clash / ASN / 信誉）…"
                : "正在执行轻量网络与进程检查…";
            using var cycleTimeout = CancellationTokenSource.CreateLinkedTokenSource(_checkCancellation.Token);
            cycleTimeout.CancelAfter(TimeSpan.FromSeconds(full ? 45 : 20));
            var report = await _engine.RunAsync(_config, full, cycleTimeout.Token);
            cycleTimeout.Token.ThrowIfCancellationRequested();
            if (full || report.Network.ContextChanged)
            {
                _lastFullCheck = DateTimeOffset.UtcNow;
                _fullCheckPending = false;
            }
            report = report with
            {
                Network = report.Network with
                {
                    LastCycleDurationMs = sw.ElapsedMilliseconds,
                    LastCycleTimedOut = false
                }
            };
            _lastReport = report;
            Render(report);
            await ApplyProtectionDecisionAsync(report, allowClearBlock: false);

            if (full &&
                _timezoneRecoveryReady &&
                !report.Network.ProxyPathSkipped &&
                report.Network.HelperAlive &&
                !_config.IsCheckDisabled(GuardianCheckIds.Timezone))
            {
                await EnsureExitTimezoneAsync(report);
            }

            sw.Stop();
            if (full)
            {
                _logger.LogAction(
                    "full-check",
                    report.CanRecover ? "ok" : "warn",
                    sw.ElapsedMilliseconds,
                    report.Checks,
                    _config.LoggingEnabled);
            }

            return _lastReport;
        }
        catch (OperationCanceledException) when (_exiting)
        {
            return null;
        }
        catch (OperationCanceledException)
        {
            _fullCheckPending = true;
            sw.Stop();
            var timeoutMsg = $"监控循环超时（{(full ? "完整检查 >45s" : "轻量检查 >20s")}），已保持当前安全状态";
            LastCheckText.Text = timeoutMsg;
            if (_lastReport is not null)
            {
                _lastReport = EvidenceFreshness.AfterTimeout(_lastReport, sw.ElapsedMilliseconds);
                Render(_lastReport);
                await ApplyProtectionDecisionAsync(_lastReport, allowClearBlock: false);
            }

            if (_blocked)
            {
                SetProtectionState("已阻断", "StatusWarnBackgroundBrush", "StatusWarnBrush");
            }

            _logger.LogAction(full ? "full-check-timeout" : "light-check-timeout", "timeout", sw.ElapsedMilliseconds, enabled: _config.LoggingEnabled);
            return _lastReport;
        }
        catch (Exception exception)
        {
            _fullCheckPending = true;
            if (_lastReport is not null)
            {
                _lastReport = EvidenceFreshness.AfterFailedCheck(_lastReport, sw.ElapsedMilliseconds, false);
                Render(_lastReport);
            }
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

    private async Task ApplyProtectionDecisionAsync(GuardianReport report, bool allowClearBlock = false)
    {
        var decision = ProtectionPolicyEvaluator.Evaluate(report, _blocked, _ignoreWebRtc, allowClearBlock);
        switch (decision.Action)
        {
            case ProtectionAction.ApplyBlockAndTerminate:
            {
                var helperResult = await SendHelperAsync("apply-block", report);
                if (helperResult.Success)
                {
                    _blocked = true;
                    TripReasonText.Text = decision.TripReason;
                    SaveGuardianState(true, decision.TripReason, DateTimeOffset.UtcNow, report.ObservedAt);
                    await SendHelperAsync("terminate-tree", report);
                    SetProtectionState("已阻断", "StatusWarnBackgroundBrush", "StatusWarnBrush");
                    _logger.LogAction("trip-block", "blocked", 0, report.Checks, _config.LoggingEnabled);
                }
                else
                {
                    TripReasonText.Text = $"{decision.TripReason}；阻断动作失败：{helperResult.Detail}";
                    SetProtectionState("阻断失败", "StatusErrorBackgroundBrush", "StatusErrorBrush");
                }

                break;
            }
            case ProtectionAction.EnforceExistingBlockTerminateOnly:
            {
                await SendHelperAsync("apply-block", report);
                await SendHelperAsync("terminate-tree", report);
                TripReasonText.Text = decision.TripReason;
                SaveGuardianState(true, decision.TripReason, DateTimeOffset.UtcNow, report.ObservedAt);
                SetProtectionState("已阻断", "StatusWarnBackgroundBrush", "StatusWarnBrush");
                _logger.LogAction("enforce-block", "blocked", 0, report.Checks, _config.LoggingEnabled);
                break;
            }
            case ProtectionAction.ClearBlock:
            {
                var helperResult = await SendHelperAsync("clear-block", report);
                if (helperResult.Success)
                {
                    _blocked = false;
                    SaveGuardianState(false, string.Empty, null, report.ObservedAt);
                    TripReasonText.Text = "暂无";
                    SetReportProtectionState(report);
                }
                else
                {
                    TripReasonText.Text = $"解除阻断失败：{helperResult.Detail}";
                }

                break;
            }
            case ProtectionAction.StayBlocked:
            {
                if (!string.IsNullOrWhiteSpace(decision.TripReason))
                {
                    TripReasonText.Text = decision.TripReason;
                }
                else if (string.IsNullOrWhiteSpace(TripReasonText.Text) || TripReasonText.Text == "暂无")
                {
                    TripReasonText.Text = "当前仍处于阻断锁定中，点击「检查并解除阻断」确认恢复";
                }

                SetProtectionState("已阻断", "StatusWarnBackgroundBrush", "StatusWarnBrush");
                SaveGuardianState(true, TripReasonText.Text, _stateStore.Load().BlockedAt ?? DateTimeOffset.UtcNow, report.ObservedAt);
                break;
            }
            default:
            {
                TripReasonText.Text = decision.BlockingFailures.Count == 0
                    ? "暂无"
                    : decision.TripReason;
                SetReportProtectionState(report);
                SaveGuardianState(false, string.Empty, null, report.ObservedAt);
                break;
            }
        }
    }

    private IReadOnlyList<CheckResult> GetEffectiveBlockingFailures(GuardianReport report) =>
        ProtectionPolicyEvaluator.GetEffectiveBlockingFailures(report, _ignoreWebRtc);

    private static string FormatTripReason(IReadOnlyList<CheckResult> failures) =>
        ProtectionPolicyEvaluator.FormatTripReason(failures);

    private void Render(GuardianReport report)
    {
        var previousSelectedId = _selectedCheckId;
        _checks.Clear();
        CheckResult? restoredSelection = null;
        foreach (var check in report.Checks)
        {
            _checks.Add(check);
            if (!string.IsNullOrEmpty(previousSelectedId) &&
                string.Equals(check.Id, previousSelectedId, StringComparison.OrdinalIgnoreCase))
            {
                restoredSelection = check;
            }
        }

        if (restoredSelection is not null)
        {
            ChecksList.SelectedItem = restoredSelection;
            SelectedEvidenceHeaderText.Text = $"选中项：{restoredSelection.Title} ({restoredSelection.Id})";
            SelectedEvidenceText.Text = UiPresentationState.FormatCheckEvidence(restoredSelection);
        }

        var okCount = report.Checks.Count(c => c.Status == CheckStatus.Ok);
        var warnCount = report.Checks.Count(c => c.Status == CheckStatus.Warn);
        var failCount = report.Checks.Count(c => c.Status == CheckStatus.Fail);
        var skipCount = report.Checks.Count(c => c.Status == CheckStatus.Skip);
        var unknownCount = report.Checks.Count(c => c.Status == CheckStatus.Unknown);
        CheckSummaryText.Text = $"{okCount} 通过 · {warnCount} 警告 · {failCount} 失败" +
                                (unknownCount > 0 ? $" · {unknownCount} 未验证" : string.Empty) +
                                (skipCount > 0 ? $" · {skipCount} 跳过" : string.Empty);

        var issues = GetEffectiveBlockingFailures(report)
            .Select(check => $"{check.Title}（{check.Status}）：{check.Detail}")
            .ToArray();
        if (_blocked && issues.Length > 0)
        {
            TripReasonText.Text = string.Join("；", issues);
        }
        else if (!_blocked)
        {
            TripReasonText.Text = issues.Length == 0 ? "暂无" : string.Join("；", issues);
        }

        AdapterText.Text = string.IsNullOrWhiteSpace(report.Network.AdapterName)
            ? "未识别"
            : report.Network.AdapterName;
        ProxyClientText.Text = string.IsNullOrWhiteSpace(report.Network.ProxyClientDetail)
            ? report.Network.ProxyClientName
            : report.Network.ProxyClientDetail;

        var uiDecision = UiPresentationState.Evaluate(report, _blocked, _ignoreWebRtc, TripReasonText.Text);
        ExitIpText.Text = report.Network.SystemProxyConfigured
            ? uiDecision.ExitPathSummary
            : string.IsNullOrWhiteSpace(report.Network.ExitIp)
                ? string.IsNullOrWhiteSpace(report.Network.Ipv4ProbeDetail)
                    ? "未取得"
                    : "未取得（见检查详情）"
                : $"{report.Network.ExitIp} / {report.Network.ExitCountry}";
        BtnLaunchClaude.ToolTip = uiDecision.LaunchGateReason;

        ExitIpv6Text.Text = report.Network.PublicIpv6Routes is { Count: > 0 }
            ? $"IPv6 风险：{string.Join("、", report.Network.PublicIpv6Routes)}"
            : string.IsNullOrWhiteSpace(report.Network.ExitIpv6)
                ? report.Network.HasIpv6
                    ? $"IPv6 出口：未取得{FormatProbeDetail(report.Network.Ipv6ProbeDetail)}"
                    : "IPv6 出口：未启用"
                : $"{report.Network.ExitIpv6} / {report.Network.ExitIpv6Country}";
        var ipv6HasNoPublicEgress = report.Network.Ipv6ProbeDetail.Contains(
            "返回的地址不是 IPv6",
            StringComparison.OrdinalIgnoreCase);
        ExitIpv6Text.Foreground = report.Network.PublicIpv6Routes is { Count: > 0 }
            ? (WpfBrush)FindResource("StatusErrorBrush")
            : report.Network.HasIpv6 &&
              string.IsNullOrWhiteSpace(report.Network.ExitIpv6) &&
              !ipv6HasNoPublicEgress
                ? (WpfBrush)FindResource("StatusWarnBrush")
                : (WpfBrush)FindResource("MutedBrush");

        DnsText.Text = report.Network.DnsServers.Count == 0
            ? "未取得"
            : string.Join(", ", report.Network.DnsServers);
        DnsSubText.Text = !string.IsNullOrWhiteSpace(report.Network.DnsProbeDetail)
            ? report.Network.DnsProbeDetail
            : !string.IsNullOrWhiteSpace(report.Network.ClashRulesDetail)
                ? report.Network.ClashRulesDetail
                : "DNS 列表已读取";

        ProcessText.Text = $"{report.ProtectedProcesses.Count} 个进程";
        RenderWfpBadge(report.Network.WfpPolicyState, report.Network.WfpPolicyDetail);

        TimezoneText.Text = string.IsNullOrWhiteSpace(report.Network.ExitWindowsTimezone)
            ? "未取得出口时区"
            : $"{report.Network.ExitTimezone} → {report.Network.ExitWindowsTimezone}";
        TimezoneStatusText.Text = string.IsNullOrWhiteSpace(_timezoneOperationError)
            ? $"系统：{report.Network.CurrentWindowsTimezone}"
            : _timezoneOperationError;
        TimezoneStatusText.Foreground = string.IsNullOrWhiteSpace(_timezoneOperationError)
            ? (WpfBrush)FindResource("MutedBrush")
            : (WpfBrush)FindResource("StatusWarnBrush");
        LocaleStatusText.Text = string.IsNullOrWhiteSpace(report.Network.CurrentLocale)
            ? "地区格式：未读取"
            : $"系统 Locale：{report.Network.CurrentLocale}" +
              (string.IsNullOrWhiteSpace(report.Network.ExpectedLocale) ? string.Empty : $"（目标 {report.Network.ExpectedLocale}）");

        WebRtcText.Text = string.Join(
            Environment.NewLine,
            BuildWebRtcLines(report));
        IgnoreWebRtcCheckBox.ToolTip = _ignoreWebRtc
            ? "当前仅忽略 WebRTC 未验证状态，检测结果仍显示在面板中。确认泄露时仍会阻断网络。"
            : "WebRTC 未验证不会被当作泄露。发现非 VPN 出口的公网候选地址时会触发阻断。";
        ConnectionsText.Text = report.Network.ActiveConnections.Count == 0
            ? "暂无已建立 TCP 连接"
            : string.Join(Environment.NewLine, report.Network.ActiveConnections);
        LastCheckText.Text = $"最近检查：{report.ObservedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss}（{report.Network.LastCycleDurationMs} ms）";
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

    private void RenderWfpBadge(string state, string detail)
    {
        WfpDetailText.Text = string.IsNullOrWhiteSpace(detail) ? $"WFP 状态：{state}" : detail;
        switch (state?.Trim().ToLowerInvariant())
        {
            case "active":
                WfpBadgeText.Text = _config.WfpAllowLoopback ? "WFP：TUN+回环" : "WFP：TUN-only";
                WfpBadgeText.Foreground = (WpfBrush)FindResource("StatusOkBrush");
                WfpBadgeBorder.Background = (WpfBrush)FindResource("StatusOkBackgroundBrush");
                break;
            case "stale":
                WfpBadgeText.Text = "WFP：已过期";
                WfpBadgeText.Foreground = (WpfBrush)FindResource("StatusWarnBrush");
                WfpBadgeBorder.Background = (WpfBrush)FindResource("StatusWarnBackgroundBrush");
                break;
            default:
                WfpBadgeText.Text = _config.WfpStrictEnabled ? "WFP：待启用" : "WFP：未启用";
                WfpBadgeText.Foreground = (WpfBrush)FindResource(_config.WfpStrictEnabled ? "StatusErrorBrush" : "MutedBrush");
                WfpBadgeBorder.Background = (WpfBrush)FindResource(_config.WfpStrictEnabled ? "StatusErrorBackgroundBrush" : "StatusUnknownBackgroundBrush");
                break;
        }
    }

    private void SetReportProtectionState(GuardianReport report)
    {
        var badge = UiPresentationState.ComputeBadge(report, blocked: false, _ignoreWebRtc);
        SetProtectionState(badge.Label, badge.BackgroundResourceKey, badge.ForegroundResourceKey);
    }

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
        ProtectionStateBorder.Background = (WpfBrush)FindResource(backgroundResource);
        ProtectionStateText.Foreground = (WpfBrush)FindResource(foregroundResource);
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
            LastCheckText.Text,
            WfpBadgeText.Text,
            AccountSubText.Text);
    }

    private async Task<HelperStatusSnapshot?> QueryHelperStatusAsync(
        string adapterGuid,
        bool allowLoopback,
        CancellationToken cancellationToken)
    {
        var result = await HelperPipeClient.SendAsync(
            "status",
            null,
            adapterGuid: adapterGuid,
            allowLoopback: allowLoopback,
            timeoutMs: 4_000,
            cancellationToken: cancellationToken);
        if (!result.Success)
        {
            return new HelperStatusSnapshot(
                HelperAlive: false,
                HelperDetail: $"管理员助手离线或未响应：{result.Detail}",
                WfpState: null,
                WfpDetail: null,
                FirewallApiOk: false,
                FirewallActiveRuleCount: 0,
                FirewallDetail: "管理员助手离线，无法核验防火墙规则");
        }

        return new HelperStatusSnapshot(
            HelperAlive: true,
            HelperDetail: result.HelperDetail ?? "管理员助手受限命名管道在线",
            WfpState: result.WfpState,
            WfpDetail: result.WfpDetail,
            FirewallApiOk: result.FirewallApiOk ?? false,
            FirewallActiveRuleCount: result.FirewallActiveRuleCount ?? 0,
            FirewallDetail: result.FirewallDetail ?? string.Empty,
            FirewallPolicyEffective: result.FirewallPolicyEffective,
            TcpOnlyState: result.TcpOnlyState,
            TcpOnlyDetail: result.TcpOnlyDetail ?? string.Empty);
    }

    private async Task ApplySavedTcpOnlyAsync()
    {
        var result = await SendHelperAsync(_config.TcpOnlyEnabled ? "tcp-only-enable" : "tcp-only-disable", null);
        if (!result.Success)
            AppendToolOutput("[警告] TCP-only 策略未确认：" + result.Detail);
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
            timezoneId: state.OriginalWindowsTimezone);
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
        var (ready, error) = await HelperPipeClient.EnsureStartedAsync();
        if (!ready)
        {
            _timezoneOperationError = error;
        }

        return ready;
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
        var originalTimezone = state.TimezoneOverrideActive && !string.IsNullOrWhiteSpace(state.OriginalWindowsTimezone)
            ? state.OriginalWindowsTimezone
            : current;
        var updatedState = state with
        {
            TimezoneOverrideActive = true,
            OriginalWindowsTimezone = originalTimezone,
            AppliedWindowsTimezone = target,
            TimezoneOverrideAt = DateTimeOffset.UtcNow
        };
        _stateStore.Save(updatedState);

        var result = await SendHelperAsync("apply-timezone", report, timezoneId: target);
        if (!result.Success)
        {
            _timezoneOperationError = $"系统时区修改失败：{result.Detail}";
            if (!state.TimezoneOverrideActive)
            {
                _stateStore.Save(state with
                {
                    TimezoneOverrideActive = false,
                    OriginalWindowsTimezone = null,
                    AppliedWindowsTimezone = null,
                    TimezoneOverrideAt = null
                });
            }
            else
            {
                _stateStore.Save(state);
            }

            Render(report);
            return;
        }

        _timezoneOperationError = string.Empty;
        TimezoneStatusText.Text = $"已临时切换：{target}，退出时恢复 {originalTimezone}";
        ApplyTimezoneResultToReport(report, target);
    }

    private void ApplyTimezoneResultToReport(GuardianReport report, string target)
    {
        var checks = report.Checks
            .Select(check => check.Id == GuardianCheckIds.Timezone
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
            timezoneId: state.OriginalWindowsTimezone);
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

    private static Task<HelperCallResult> SendHelperAsync(
        string command,
        GuardianReport? report,
        string? timezoneId = null,
        string? adapterGuid = null,
        bool allowLoopback = false,
        IReadOnlyList<string>? adapterNames = null) =>
        HelperPipeClient.SendAsync(command, report, timezoneId, adapterGuid, allowLoopback, adapterNames);

    private static string FormatProbeDetail(string detail) =>
        string.IsNullOrWhiteSpace(detail) ? string.Empty : $"（{detail}）";

    private sealed record ProxyModeOption(string Key, string Label);
}
