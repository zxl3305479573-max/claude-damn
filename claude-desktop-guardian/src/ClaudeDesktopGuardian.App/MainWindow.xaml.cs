using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Forms;
using ClaudeDesktopGuardian.Core;
using WpfBrush = System.Windows.Media.Brush;
using WpfButton = System.Windows.Controls.Button;
using WpfCheckBox = System.Windows.Controls.CheckBox;
using WpfComboBoxItem = System.Windows.Controls.ComboBoxItem;
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
    private readonly Dictionary<string, WpfCheckBox> _optionalCheckBoxes = new(StringComparer.OrdinalIgnoreCase);
    private readonly System.Windows.Threading.DispatcherTimer _timer;
    private readonly NotifyIcon _trayIcon;
    private readonly ToolStripMenuItem _compactWindowMenuItem;
    private readonly SemaphoreSlim _checkGate = new(1, 1);

    private GuardianConfig _config;
    private GuardianReport? _lastReport;
    private MiniStatusWindow? _compactWindow;
    private bool _blocked;
    private bool _ignoreWebRtc;
    private bool _compactWindowEnabled;
    private bool _allowExit;
    private bool _operationInProgress;
    private bool _timezoneRecoveryReady;
    private string _timezoneOperationError = string.Empty;
    private DateTimeOffset _lastFullCheck = DateTimeOffset.MinValue;

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
            Text = "Claude Desktop Guardian",
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
            _compactWindow?.Close();
            _processMonitor.Dispose();
            _checkGate.Dispose();
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
            await RunCheckAsync(true);

            if (_compactWindowEnabled)
            {
                ShowCompactWindow();
            }
        };
    }

    private void InitializeSettingsUi()
    {
        ProxyClientModeCombo.ItemsSource = ProxyClientModes.All
            .Select(key => new ProxyModeOption(key, ProxyClientModes.DisplayName(key)))
            .ToArray();

        WebRtcPolicyCombo.ItemsSource = new[]
        {
            new ProxyModeOption(WebRtcPolicies.Proxy, WebRtcPolicies.DisplayName(WebRtcPolicies.Proxy)),
            new ProxyModeOption(WebRtcPolicies.Reject, WebRtcPolicies.DisplayName(WebRtcPolicies.Reject))
        };

        OptionalChecksPanel.Children.Clear();
        _optionalCheckBoxes.Clear();
        foreach (var id in GuardianCheckIds.OptionalIds)
        {
            var title = GuardianCheckIds.OptionalTitles.GetValueOrDefault(id, id);
            var cb = new WpfCheckBox
            {
                Content = title,
                Style = (Style)FindResource("GuardianCheckBoxStyle"),
                Margin = new Thickness(0, 4, 12, 4),
                IsChecked = true
            };
            _optionalCheckBoxes[id] = cb;
            OptionalChecksPanel.Children.Add(cb);
        }
    }

    private void LoadConfigToUi(GuardianConfig cfg)
    {
        ProxyClientModeCombo.SelectedValue = ProxyClientModes.Normalize(cfg.ProxyClientMode);
        WebRtcPolicyCombo.SelectedValue = WebRtcPolicies.Normalize(cfg.WebRtcPolicy);
        ExpectedCountryBox.Text = cfg.ExpectedExitCountry ?? string.Empty;
        ExpectedIpBox.Text = cfg.ExpectedExitIp ?? string.Empty;
        ExpectedLocaleBox.Text = cfg.ExpectedLocale ?? string.Empty;
        VpnPatternBox.Text = cfg.VpnAdapterPattern ?? string.Empty;
        FlClashControllerBox.Text = cfg.FlClashController ?? string.Empty;
        ClashProxyGroupBox.Text = cfg.ClashProxyGroup;
        LightIntervalBox.Text = cfg.LightIntervalSeconds.ToString(CultureInfo.InvariantCulture);
        FullIntervalBox.Text = cfg.FullIntervalMinutes.ToString(CultureInfo.InvariantCulture);

        WfpStrictCheckBox.IsChecked = cfg.WfpStrictEnabled;
        WfpLoopbackCheckBox.IsChecked = cfg.WfpAllowLoopback;
        AllowOptionalFailuresCheckBox.IsChecked = cfg.AllowOptionalFailures;
        LoggingEnabledCheckBox.IsChecked = cfg.LoggingEnabled;

        foreach (var (id, cb) in _optionalCheckBoxes)
        {
            cb.IsChecked = !cfg.IsCheckDisabled(id);
        }

        IpRepUrlBox.Text = cfg.IpReputation?.Url ?? string.Empty;
        IpRepKeyBox.Clear();
        IpRepKeyStatusText.Text = !string.IsNullOrEmpty(cfg.IpReputation?.Key)
            ? "已配置 API Key（留空且 URL 未变时保持原密钥）"
            : "未配置 API Key";
        IpRepThresholdBox.Text = (cfg.IpReputation?.Threshold ?? 25).ToString("0.#", CultureInfo.InvariantCulture);
        IpRepCacheDaysBox.Text = (cfg.IpReputation?.CacheDays ?? 7).ToString(CultureInfo.InvariantCulture);
    }

    private bool TryBeginOperation(string statusHint)
    {
        if (_operationInProgress)
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
            RecoverButton,
            BtnEnableWfpQuick,
            BtnDisableWfpQuick,
            BtnRefreshAccounts,
            BtnSwitchA,
            BtnSwitchB,
            BtnSwitchC,
            BtnSwitchD,
            BtnExportSnapshot,
            BtnImportSnapshot,
            BtnSaveKeepPaths,
            BtnOneClickFix,
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

            // Always issue idempotent clear-block and wfp-disable on clean exit so no persistent rules stay behind
            var clearRes = await SendHelperAsync("clear-block", _lastReport);
            if (clearRes.Success)
            {
                SaveGuardianState(false, string.Empty, null, _lastReport?.ObservedAt);
                _blocked = false;
            }

            await SendHelperAsync("wfp-disable", null);

            _allowExit = true;
            _trayIcon.Visible = false;
            Close();
        }
        catch (Exception ex)
        {
            ShowFromTray();
            WpfMessageBox.Show($"退出恢复时发生错误：{ex.Message}", "退出失败", MessageBoxButton.OK, MessageBoxImage.Warning);
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

        await _checkGate.WaitAsync();
        var sw = Stopwatch.StartNew();
        try
        {
            LastCheckText.Text = $"正在单项复检 {checkId}…";
            var report = _lastReport is null
                ? await _engine.RunAsync(_config, full: true, CancellationToken.None)
                : await _engine.RunSingleCheckAsync(_lastReport, checkId, _config, CancellationToken.None);
            _lastReport = report;
            Render(report);
            // Single-item retest can trip a block if it fails, but never auto-clears an existing block
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
        catch (Exception ex)
        {
            TripReasonText.Text = $"单项复检失败：{ex.Message}";
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
                WpfMessageBox.Show(
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
            _logger.LogAction("recover", "ok", 0, report.Checks, _config.LoggingEnabled);
            await RunCheckAsync(false);
        }
        finally
        {
            EndOperation();
        }
    }

    private async void EnableWfpButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBeginOperation("正在启用/刷新 WFP 内核出站锁…"))
        {
            return;
        }

        try
        {
            if (_lastReport is null || string.IsNullOrWhiteSpace(_lastReport.Network.AdapterGuid))
            {
                await RunCheckAsync(true);
            }

            var adapterGuid = _lastReport?.Network.AdapterGuid ?? string.Empty;
            if (string.IsNullOrWhiteSpace(adapterGuid))
            {
                AppendToolOutput("[失败] 当前未检测到在线 VPN/TUN 网卡，无法启用 WFP 出站锁。");
                return;
            }

            var sw = Stopwatch.StartNew();
            var result = await SendHelperAsync(
                "wfp-enable",
                _lastReport,
                adapterGuid: adapterGuid,
                allowLoopback: _config.WfpAllowLoopback);
            sw.Stop();
            AppendToolOutput(result.Success
                ? $"[通过] {result.Detail}"
                : $"[失败] 启用 WFP 出站锁失败：{result.Detail}");
            _logger.LogAction("wfp-enable", result.Success ? "ok" : "fail", sw.ElapsedMilliseconds, enabled: _config.LoggingEnabled);
            await RunCheckAsync(true);
        }
        catch (Exception ex)
        {
            AppendToolOutput($"[失败] 启用 WFP 异常：{ex.Message}");
        }
        finally
        {
            EndOperation();
        }
    }

    private async void DisableWfpButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBeginOperation("正在移除 WFP 内核出站锁…"))
        {
            return;
        }

        try
        {
            var sw = Stopwatch.StartNew();
            var result = await SendHelperAsync("wfp-disable", null);
            sw.Stop();
            AppendToolOutput(result.Success
                ? $"[通过] {result.Detail}"
                : $"[失败] 移除 WFP 出站锁失败：{result.Detail}");
            _logger.LogAction("wfp-disable", result.Success ? "ok" : "fail", sw.ElapsedMilliseconds, enabled: _config.LoggingEnabled);
            await RunCheckAsync(true);
        }
        catch (Exception ex)
        {
            AppendToolOutput($"[失败] 移除 WFP 异常：{ex.Message}");
        }
        finally
        {
            EndOperation();
        }
    }

    private async void AdaptRegionButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBeginOperation("正在按当前出口重新适配国家、时区与 Locale…"))
        {
            return;
        }

        var sw = Stopwatch.StartNew();
        var log = new StringBuilder();
        log.AppendLine($"# 重新适配出口地区 (set-region) {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        try
        {
            var probeRes = await _environmentProbe.ProbeRegionForAdaptAsync(_config, CancellationToken.None);
            if (!probeRes.Success)
            {
                log.AppendLine($"[失败] {probeRes.Error}");
                ToolOutputTextBox.Text = log.ToString();
                _logger.LogAction("set-region", "fail", sw.ElapsedMilliseconds, enabled: _config.LoggingEnabled);
                return;
            }

            _config = _configStore.Save(
                _config with
                {
                    ExpectedExitCountry = probeRes.Country,
                    ExpectedLocale = probeRes.Locale
                },
                preserveExistingApiKeyIfEmpty: true);
            LoadConfigToUi(_config);
            log.AppendLine($"[通过] 已锁定出口目标：国家={probeRes.Country}，IANA 时区={probeRes.IanaTimezone}（Windows={probeRes.WindowsTimezone}），Locale={probeRes.Locale}（源={probeRes.Source}）");

            // Apply system timezone via privileged helper (preserving original pre-override timezone)
            var state = _stateStore.Load();
            TimeZoneInfo.ClearCachedData();
            var currentTz = TimeZoneInfo.Local.Id;
            if (!string.Equals(currentTz, probeRes.WindowsTimezone, StringComparison.OrdinalIgnoreCase))
            {
                var originalTz = state.TimezoneOverrideActive && !string.IsNullOrWhiteSpace(state.OriginalWindowsTimezone)
                    ? state.OriginalWindowsTimezone
                    : currentTz;
                _stateStore.Save(state with
                {
                    TimezoneOverrideActive = true,
                    OriginalWindowsTimezone = originalTz,
                    AppliedWindowsTimezone = probeRes.WindowsTimezone,
                    TimezoneOverrideAt = DateTimeOffset.UtcNow
                });
                var tzRes = await SendHelperAsync("apply-timezone", _lastReport, timezoneId: probeRes.WindowsTimezone);
                if (tzRes.Success)
                {
                    _timezoneOperationError = string.Empty;
                    log.AppendLine($"[通过] 系统时区已切换至 {probeRes.WindowsTimezone}（退出时恢复 {originalTz}）");
                }
                else
                {
                    _timezoneOperationError = $"系统时区切换失败：{tzRes.Detail}";
                    if (!state.TimezoneOverrideActive)
                    {
                        _stateStore.Save(state);
                    }
                    log.AppendLine($"[警告] {_timezoneOperationError}");
                }
            }
            else
            {
                log.AppendLine($"[通过] 系统时区已是 {probeRes.WindowsTimezone}");
            }

            // Apply user locale via Set-Culture
            var script = $"$ErrorActionPreference='Stop'; Set-Culture '{probeRes.Locale.Replace("'", "''")}'";
            var localeOk = await Task.Run(() => RunPowerShellUserScript(script, out var err)
                ? (true, $"当前用户区域格式已设为 {probeRes.Locale}")
                : (false, $"区域格式同步失败：{err}"));
            log.AppendLine(localeOk.Item1 ? $"[通过] {localeOk.Item2}" : $"[警告] {localeOk.Item2}");

            ToolOutputTextBox.Text = log.ToString();
            await RunCheckAsync(true);
            sw.Stop();
            log.AppendLine($"地区适配完成（耗时 {sw.ElapsedMilliseconds} ms）。");
            ToolOutputTextBox.Text = log.ToString();
            _logger.LogAction("set-region", "ok", sw.ElapsedMilliseconds, enabled: _config.LoggingEnabled);
        }
        catch (Exception ex)
        {
            sw.Stop();
            log.AppendLine($"[失败] 地区适配异常：{ex.Message}");
            ToolOutputTextBox.Text = log.ToString();
            _logger.LogAction("set-region", "fail", sw.ElapsedMilliseconds, enabled: _config.LoggingEnabled);
        }
        finally
        {
            EndOperation();
        }
    }

    private async void OneClickFixButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBeginOperation("正在执行一键修复环境…"))
        {
            return;
        }

        var sw = Stopwatch.StartNew();
        var log = new StringBuilder();
        log.AppendLine($"# 一键修复执行 {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        try
        {
            var report = _lastReport ?? await RunCheckAsync(true);

            // 1. Flush DNS via privileged helper
            var dnsRes = await SendHelperAsync("flush-dns", null);
            log.AppendLine(dnsRes.Success
                ? $"[通过] DNS 缓存刷新：{dnsRes.Detail}"
                : $"[警告] DNS 缓存刷新失败：{dnsRes.Detail}");

            // 2. Sync timezone if mismatched
            if (report is not null && !string.IsNullOrWhiteSpace(report.Network.ExitWindowsTimezone))
            {
                if (!string.Equals(report.Network.CurrentWindowsTimezone, report.Network.ExitWindowsTimezone, StringComparison.OrdinalIgnoreCase))
                {
                    await EnsureExitTimezoneAsync(report);
                    log.AppendLine(string.IsNullOrEmpty(_timezoneOperationError)
                        ? $"[通过] 时区同步：已切换至 {report.Network.ExitWindowsTimezone}"
                        : $"[警告] 时区同步：{_timezoneOperationError}");
                }
                else
                {
                    log.AppendLine($"[通过] 时区已匹配：{report.Network.CurrentWindowsTimezone}");
                }
            }

            // 3. Disable IPv6 binding ONLY on leaking non-VPN adapters
            var leakingAdapters = report?.Network.PublicIpv6Routes ?? Array.Empty<string>();
            if (leakingAdapters.Count > 0)
            {
                var ipv6Res = await SendHelperAsync("disable-ipv6-adapters", null, adapterNames: leakingAdapters);
                log.AppendLine(ipv6Res.Success
                    ? $"[通过] IPv6 旁路治理：{ipv6Res.Detail}"
                    : $"[警告] IPv6 旁路治理失败：{ipv6Res.Detail}");
            }
            else
            {
                log.AppendLine("[通过] 非 VPN 网卡未发现公网/NAT64 IPv6 路由，无需修改网卡绑定");
            }

            // 4. Mode-aware Clash Verge pinned rules repair (with Merge cleanup, reload verification & rollback)
            if (Directory.Exists(ClashInspector.FindClashVergeDir()))
            {
                var ruleFix = await _clashInspector.RepairClashVergeRulesAsync(_config, CancellationToken.None);
                log.AppendLine(ruleFix.Success
                    ? $"[通过] Clash 置顶规则：{ruleFix.Message}"
                    : $"[警告] Clash 置顶规则：{ruleFix.Message}");
            }

            // 5. Refresh WFP if strict mode enabled and TUN adapter is up
            if (_config.WfpStrictEnabled && !string.IsNullOrWhiteSpace(report?.Network.AdapterGuid))
            {
                var wfpRes = await SendHelperAsync(
                    "wfp-enable",
                    report,
                    adapterGuid: report!.Network.AdapterGuid,
                    allowLoopback: _config.WfpAllowLoopback);
                log.AppendLine(wfpRes.Success
                    ? $"[通过] WFP 规则刷新：{wfpRes.Detail}"
                    : $"[警告] WFP 规则刷新失败：{wfpRes.Detail}");
            }

            log.AppendLine("正在执行修复后完整复检…");
            ToolOutputTextBox.Text = log.ToString();
            var fresh = await RunCheckAsync(true);
            sw.Stop();
            _logger.LogAction("one-click-fix", fresh?.CanRecover == true ? "ok" : "warn", sw.ElapsedMilliseconds, fresh?.Checks, _config.LoggingEnabled);
            log.AppendLine($"修复流程完成（耗时 {sw.ElapsedMilliseconds} ms）。");
            ToolOutputTextBox.Text = log.ToString();
        }
        catch (Exception ex)
        {
            sw.Stop();
            log.AppendLine($"[失败] 一键修复异常：{ex.Message}");
            ToolOutputTextBox.Text = log.ToString();
            _logger.LogAction("one-click-fix", "fail", sw.ElapsedMilliseconds, enabled: _config.LoggingEnabled);
        }
        finally
        {
            EndOperation();
        }
    }

    private async void SyncLocaleButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBeginOperation("正在同步当前用户区域格式…"))
        {
            return;
        }

        try
        {
            var target = !string.IsNullOrWhiteSpace(_config.ExpectedLocale)
                ? _config.ExpectedLocale!
                : !string.IsNullOrWhiteSpace(_lastReport?.Network.ExpectedLocale)
                    ? _lastReport!.Network.ExpectedLocale
                    : CountryDefaults.GetExpectedLocale(_config.ExpectedExitCountry ?? _lastReport?.Network.ExitCountry);

            if (string.IsNullOrWhiteSpace(target) ||
                !Regex.IsMatch(target, "^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$"))
            {
                AppendToolOutput("[失败] 无法确定合法的目标地区 Locale，请先在「检查与防护设置」填写或等待出口识别。");
                return;
            }

            var script = $"$ErrorActionPreference='Stop'; Set-Culture '{target.Replace("'", "''")}'";
            var ok = await Task.Run(() => RunPowerShellUserScript(script, out var error)
                ? (true, $"已同步当前用户系统区域格式为 {target}（部分应用重启后生效）")
                : (false, $"同步地区 Locale 失败：{error}"));

            AppendToolOutput(ok.Item1 ? $"[通过] {ok.Item2}" : $"[失败] {ok.Item2}");
            _logger.LogAction("sync-locale", ok.Item1 ? "ok" : "fail", 0, enabled: _config.LoggingEnabled);
            await RunCheckAsync(true);
        }
        catch (Exception ex)
        {
            AppendToolOutput($"[失败] 同步 Locale 异常：{ex.Message}");
        }
        finally
        {
            EndOperation();
        }
    }

    private async void ClashStatusButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            ToolOutputTextBox.Text = "正在查询 Clash / FlClash 运行模式与内核置顶规则…";
            var audit = await _clashInspector.InspectAsync(_config, CancellationToken.None);
            var sb = new StringBuilder();
            sb.AppendLine($"# Clash 路由规则审计 {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"运行模式：{audit.Mode}");
            sb.AppendLine($"审计结果：{audit.Status}");
            sb.AppendLine($"WebRTC 策略：{WebRtcPolicies.DisplayName(_config.WebRtcPolicy)}");
            sb.AppendLine($"详情：{audit.Detail}");
            if (!string.IsNullOrWhiteSpace(audit.EndpointBaseUrl))
            {
                sb.AppendLine($"控制接口：{audit.EndpointBaseUrl}（来源：{audit.EndpointSource}）");
            }

            if (audit.HeadRules.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("前 18 条内核规则：");
                foreach (var rule in audit.HeadRules)
                {
                    sb.AppendLine("  " + rule);
                }
            }

            ToolOutputTextBox.Text = sb.ToString();
        }
        catch (Exception ex)
        {
            ToolOutputTextBox.Text = $"[失败] 查询 Clash 状态失败：{ex.Message}";
        }
    }

    private async void WriteClashRulesButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBeginOperation("正在按运行模式修复 Clash Verge 置顶规则…"))
        {
            return;
        }

        try
        {
            ToolOutputTextBox.Text = "正在识别 Clash 运行模式、清理旧 Merge.yaml 并验证内核 /rules…";
            var result = await _clashInspector.RepairClashVergeRulesAsync(_config, CancellationToken.None);

            var sb = new StringBuilder();
            sb.AppendLine($"# 修复 Clash Verge 置顶规则 {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine(result.Success
                ? $"[通过] {result.Message}"
                : $"[失败] {result.Message}");
            ToolOutputTextBox.Text = sb.ToString();
            _logger.LogAction("write-clash-rules", result.Success ? "ok" : "fail", 0, enabled: _config.LoggingEnabled);
            await RunCheckAsync(true);
        }
        catch (Exception ex)
        {
            ToolOutputTextBox.Text = $"[失败] 写入 Clash 置顶规则异常：{ex.Message}";
        }
        finally
        {
            EndOperation();
        }
    }

    private async void FingerprintButton_Click(object sender, RoutedEventArgs e)
    {
        ToolOutputTextBox.Text = "正在执行只读设备指纹体检…";
        var report = await Task.Run(FingerprintInspector.RunReport);
        ToolOutputTextBox.Text = report;
        _logger.LogAction("fingerprint-check", "ok", 0, enabled: _config.LoggingEnabled);
    }

    private async void CliInfoButton_Click(object sender, RoutedEventArgs e)
    {
        ToolOutputTextBox.Text = "正在执行只读 Claude Code CLI 体检…";
        var report = await Task.Run(CliInspector.RunReport);
        ToolOutputTextBox.Text = report;
        _logger.LogAction("cli-check", "ok", 0, enabled: _config.LoggingEnabled);
    }

    private void ExportDiagnosticsButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = "导出脱敏诊断包",
            Filter = "ZIP 诊断包 (*.zip)|*.zip",
            FileName = $"claude-guardian-diagnostics-{DateTime.Now:yyyyMMdd-HHmmss}.zip"
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            DiagnosticsExporter.ExportZip(
                dialog.FileName,
                _config,
                _stateStore.Load(),
                _lastReport,
                _logger);
            ToolOutputTextBox.Text = $"[通过] 脱敏诊断包已导出至：{dialog.FileName}\r\n包含：environment.json、recent-status.json、config-redacted.json（已剔除 IP 与 API Key）、guardian.log（严格脱敏）。";
            _logger.LogAction("export-diagnostics", "ok", 0, enabled: _config.LoggingEnabled);
        }
        catch (Exception ex)
        {
            ToolOutputTextBox.Text = $"[失败] 导出诊断包失败：{ex.Message}";
        }
    }

    private void OpenSafeBrowserButton_Click(object sender, RoutedEventArgs e)
    {
        var url = SafeBrowserUrlBox.Text?.Trim() ?? string.Empty;
        var result = SafeBrowserLauncher.Launch(url, _config, _lastReport?.Network);
        AppendToolOutput(result.Success ? $"[通过] {result.Message}" : $"[拦截] {result.Message}");
        _logger.LogAction("safe-browser", result.Success ? "ok" : "fail", 0, enabled: _config.LoggingEnabled);
    }

    private async void LaunchClaudeButton_Click(object sender, RoutedEventArgs e)
    {
        await LaunchClaudeSafeAsync();
    }

    private async Task LaunchClaudeSafeAsync()
    {
        if (!TryBeginOperation("正在执行安全启动前环境校验…"))
        {
            return;
        }

        try
        {
            var report = _lastReport ?? await RunCheckAsync(true);
            var gate = ProtectionPolicyEvaluator.EvaluateLaunchGate(report, _blocked, _ignoreWebRtc);
            if (!gate.Allowed)
            {
                ShowFromTray();
                WpfMessageBox.Show(
                    $"环境安全门禁已拦截 Claude 启动：\n{gate.Reason}",
                    "禁止启动 Claude",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                _logger.LogAction("safe-launch", "blocked", 0, report?.Checks, _config.LoggingEnabled);
                return;
            }

            var target = ClaudeInstallDiscovery.FindClaudeLaunchTarget();
            if (string.IsNullOrWhiteSpace(target))
            {
                ShowFromTray();
                WpfMessageBox.Show(
                    "未找到已安装的 Claude Desktop（传统 EXE 或 MSIX），请先安装 Claude Desktop。",
                    "未找到 Claude",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = target,
                UseShellExecute = true
            });
            _logger.LogAction("safe-launch", "ok", 0, report?.Checks, _config.LoggingEnabled);
            LastCheckText.Text = $"已通过安全门禁并启动 Claude（{DateTime.Now:HH:mm:ss}）";
        }
        catch (Exception ex)
        {
            ShowFromTray();
            WpfMessageBox.Show($"启动 Claude 失败：{ex.Message}", "启动失败", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            EndOperation();
        }
    }

    private void PickProxyConfigButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "选择独立代理诊断私有配置文件",
            Filter = "JSON 配置文件 (*.json)|*.json|所有文件 (*.*)|*.*"
        };
        if (dialog.ShowDialog() == true)
        {
            ProxyDiagUrlBox.Text = dialog.FileName;
        }
    }

    private async void DiagnoseProxyButton_Click(object sender, RoutedEventArgs e)
    {
        var input = ProxyDiagUrlBox.Text?.Trim() ?? string.Empty;
        ToolOutputTextBox.Text = "正在通过指定代理探测 api.anthropic.com 与 claude.ai（不写入客户端日志或账号状态）…";
        try
        {
            var isConfigFile = input.EndsWith(".json", StringComparison.OrdinalIgnoreCase) || File.Exists(input);
            var report = isConfigFile
                ? await ProxyDiagnosticsRunner.RunFromSourcesAsync(null, input, null, CancellationToken.None)
                : await ProxyDiagnosticsRunner.RunAsync(input, CancellationToken.None);
            ToolOutputTextBox.Text = ProxyDiagnosticsRunner.FormatReportJson(report);
        }
        catch (Exception ex)
        {
            ToolOutputTextBox.Text = $"[失败] 代理诊断异常：{ex.Message}";
        }
    }

    private void ClearToolOutputButton_Click(object sender, RoutedEventArgs e)
    {
        ToolOutputTextBox.Clear();
    }

    private void RefreshAccountsButton_Click(object sender, RoutedEventArgs e)
    {
        RefreshAccountUi();
        AccountActionStatusText.Text = "账号槽位信息已刷新。";
    }

    private void RefreshAccountUi()
    {
        var slots = _accountManager.ListSlots();
        var current = slots.FirstOrDefault(s => s.IsCurrent)?.Slot;
        AccountSubText.Text = string.IsNullOrEmpty(current)
            ? "当前账号槽位：未绑定（首次切换归档至 A）"
            : $"当前活跃槽位：{current}";

        UpdateSlotCard(slots.First(s => s.Slot == "A"), SlotCardA, SlotStatusA, SlotTimeA);
        UpdateSlotCard(slots.First(s => s.Slot == "B"), SlotCardB, SlotStatusB, SlotTimeB);
        UpdateSlotCard(slots.First(s => s.Slot == "C"), SlotCardC, SlotStatusC, SlotTimeC);
        UpdateSlotCard(slots.First(s => s.Slot == "D"), SlotCardD, SlotStatusD, SlotTimeD);
    }

    private void UpdateSlotCard(
        AccountSlotInfo info,
        System.Windows.Controls.Border card,
        System.Windows.Controls.TextBlock statusText,
        System.Windows.Controls.TextBlock timeText)
    {
        statusText.Text = info.StatusText;
        timeText.Text = info.TimestampText;
        card.BorderBrush = (WpfBrush)FindResource(info.IsCurrent ? "AccentBrush" : "LineBrush");
        statusText.Foreground = (WpfBrush)FindResource(info.IsCurrent ? "StatusOkBrush" : "TextBrush");
    }

    private async void SwitchAccountButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not WpfButton { Tag: string targetSlot })
        {
            return;
        }

        if (_blocked)
        {
            AccountActionStatusText.Text = "✕ 当前处于防火墙阻断状态，请先点击底部「检查并解除阻断」确认恢复后再切换账号。";
            AccountActionStatusText.Foreground = (WpfBrush)FindResource("StatusErrorBrush");
            return;
        }

        if (!TryBeginOperation($"正在执行切换前安全复检（目标槽位 {targetSlot}）…"))
        {
            return;
        }

        AccountActionStatusText.Text = $"正在执行切换前环境安全复检（目标槽位 {targetSlot}）…";
        var sw = Stopwatch.StartNew();
        try
        {
            var report = await RunCheckAsync(true);
            var failures = report is null ? Array.Empty<CheckResult>() : GetEffectiveBlockingFailures(report);
            var healthy = !_blocked && report is not null && !report.Network.ProxyPathSkipped && failures.Count == 0;
            var reason = _blocked
                ? "当前仍处于阻断状态"
                : report is null
                    ? "未能获取环境报告"
                    : report.Network.ProxyPathSkipped
                        ? "代理或 TUN 路径不可用"
                        : FormatTripReason(failures);

            var result = await Task.Run(() => _accountManager.SwitchToSlot(targetSlot, healthy, reason, launchAfterSwitch: true));
            sw.Stop();
            AccountActionStatusText.Text = result.Success
                ? $"✓ {result.Message}"
                : $"✕ {result.Message}";
            AccountActionStatusText.Foreground = (WpfBrush)FindResource(result.Success ? "StatusOkBrush" : "StatusErrorBrush");
            RefreshAccountUi();
            UpdateCompactWindow();
            _logger.LogAction("switch-account", result.Success ? "ok" : "fail", sw.ElapsedMilliseconds, enabled: _config.LoggingEnabled);
        }
        catch (Exception ex)
        {
            AccountActionStatusText.Text = $"✕ 切换异常：{ex.Message}";
            AccountActionStatusText.Foreground = (WpfBrush)FindResource("StatusErrorBrush");
        }
        finally
        {
            EndOperation();
        }
    }

    private void SaveKeepPathsButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _accountManager.SaveKeepPathsText(KeepPathsTextBox.Text);
            AccountActionStatusText.Text = $"✓ 已保存跨账号保留路径清单（{_accountManager.KeepFilePath}）";
            AccountActionStatusText.Foreground = (WpfBrush)FindResource("StatusOkBrush");
        }
        catch (Exception ex)
        {
            AccountActionStatusText.Text = $"✕ 保存保留路径失败：{ex.Message}";
            AccountActionStatusText.Foreground = (WpfBrush)FindResource("StatusErrorBrush");
        }
    }

    private async void ExportSnapshotButton_Click(object sender, RoutedEventArgs e)
    {
        var slot = (SnapshotSlotCombo.SelectedItem as WpfComboBoxItem)?.Content?.ToString() ?? "A";
        var password = SnapshotPasswordBox.Password;
        if (string.IsNullOrEmpty(password) || password.Length < 8)
        {
            AccountActionStatusText.Text = "✕ 导出密码至少需要 8 位。";
            AccountActionStatusText.Foreground = (WpfBrush)FindResource("StatusErrorBrush");
            return;
        }

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = $"导出账号 {slot} 加密快照",
            Filter = "Claude 加密快照 (*.csnap)|*.csnap",
            FileName = $"claude-slot-{slot}-{DateTime.Now:yyyyMMdd}.csnap"
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        if (!TryBeginOperation($"正在加密导出槽位 {slot}…"))
        {
            return;
        }

        AccountActionStatusText.Text = $"正在加密导出槽位 {slot}…";
        try
        {
            var result = await Task.Run(() => _accountManager.ExportEncryptedSnapshot(slot, dialog.FileName, password));
            AccountActionStatusText.Text = result.Success ? $"✓ {result.Message}" : $"✕ {result.Message}";
            AccountActionStatusText.Foreground = (WpfBrush)FindResource(result.Success ? "StatusOkBrush" : "StatusErrorBrush");
            _logger.LogAction("export-snapshot", result.Success ? "ok" : "fail", 0, enabled: _config.LoggingEnabled);
        }
        finally
        {
            SnapshotPasswordBox.Clear();
            EndOperation();
        }
    }

    private async void ImportSnapshotButton_Click(object sender, RoutedEventArgs e)
    {
        var slot = (SnapshotSlotCombo.SelectedItem as WpfComboBoxItem)?.Content?.ToString() ?? "A";
        var password = SnapshotPasswordBox.Password;
        if (string.IsNullOrEmpty(password))
        {
            AccountActionStatusText.Text = "✕ 请先输入快照解密密码。";
            AccountActionStatusText.Foreground = (WpfBrush)FindResource("StatusErrorBrush");
            return;
        }

        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = $"导入加密快照到空槽位 {slot}",
            Filter = "Claude 加密快照 (*.csnap)|*.csnap"
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        if (!TryBeginOperation($"正在校验并解密导入到槽位 {slot}…"))
        {
            return;
        }

        AccountActionStatusText.Text = $"正在校验并解密导入到槽位 {slot}…";
        try
        {
            var result = await Task.Run(() => _accountManager.ImportEncryptedSnapshot(dialog.FileName, slot, password));
            AccountActionStatusText.Text = result.Success ? $"✓ {result.Message}" : $"✕ {result.Message}";
            AccountActionStatusText.Foreground = (WpfBrush)FindResource(result.Success ? "StatusOkBrush" : "StatusErrorBrush");
            RefreshAccountUi();
            _logger.LogAction("import-snapshot", result.Success ? "ok" : "fail", 0, enabled: _config.LoggingEnabled);
        }
        finally
        {
            SnapshotPasswordBox.Clear();
            EndOperation();
        }
    }

    private void DetectProxyGroupButton_Click(object sender, RoutedEventArgs e)
    {
        var detected = ClashInspector.DetectDefaultProxyGroup();
        ClashProxyGroupBox.Text = detected;
        SettingsStatusText.Text = $"已识别 Clash 代理组：{detected}（点击「保存设置并重新检查」后生效）";
        SettingsStatusText.Foreground = (WpfBrush)FindResource("AccentHoverBrush");
    }

    private async void SaveSettingsButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBeginOperation("正在保存设置并重新检查…"))
        {
            return;
        }

        try
        {
            if (!int.TryParse(LightIntervalBox.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var lightSec))
            {
                throw new ArgumentException("轻量检查间隔必须是整数秒");
            }

            if (!int.TryParse(FullIntervalBox.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var fullMin))
            {
                throw new ArgumentException("完整检查间隔必须是整数分钟");
            }

            IpReputationConfig? ipRep = null;
            var repUrl = IpRepUrlBox.Text.Trim();
            if (!string.IsNullOrEmpty(repUrl))
            {
                if (!double.TryParse(IpRepThresholdBox.Text.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var threshold))
                {
                    throw new ArgumentException("IP 信誉风险分阈值必须是数字（0-100）");
                }

                if (!int.TryParse(IpRepCacheDaysBox.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var cacheDays))
                {
                    throw new ArgumentException("IP 信誉缓存天数必须是整数（1-90）");
                }

                ipRep = new IpReputationConfig(repUrl, IpRepKeyBox.Password, threshold, cacheDays);
            }

            var disabledOptional = _optionalCheckBoxes
                .Where(pair => pair.Value.IsChecked != true)
                .Select(pair => pair.Key)
                .ToArray();

            var previousWfpStrict = _config.WfpStrictEnabled;
            var previousWfpLoopback = _config.WfpAllowLoopback;

            var candidate = _config with
            {
                ProxyClientMode = ProxyClientModeCombo.SelectedValue?.ToString() ?? ProxyClientModes.Auto,
                WebRtcPolicy = WebRtcPolicyCombo.SelectedValue?.ToString() ?? WebRtcPolicies.Proxy,
                ExpectedExitCountry = ExpectedCountryBox.Text.Trim(),
                ExpectedExitIp = ExpectedIpBox.Text.Trim(),
                ExpectedLocale = ExpectedLocaleBox.Text.Trim(),
                VpnAdapterPattern = VpnPatternBox.Text.Trim(),
                FlClashController = FlClashControllerBox.Text.Trim(),
                ClashProxyGroup = ClashProxyGroupBox.Text.Trim(),
                LightIntervalSeconds = lightSec,
                FullIntervalMinutes = fullMin,
                WfpStrictEnabled = WfpStrictCheckBox.IsChecked == true,
                WfpAllowLoopback = WfpLoopbackCheckBox.IsChecked == true,
                AllowOptionalFailures = AllowOptionalFailuresCheckBox.IsChecked == true,
                LoggingEnabled = LoggingEnabledCheckBox.IsChecked == true,
                DisabledOptionalChecks = disabledOptional,
                IpReputation = ipRep
            };

            _config = _configStore.Save(candidate, preserveExistingApiKeyIfEmpty: true);
            _timer.Interval = TimeSpan.FromSeconds(_config.LightIntervalSeconds);
            LoadConfigToUi(_config);

            var wfpNotice = string.Empty;
            if (_config.WfpStrictEnabled &&
                (!previousWfpStrict || previousWfpLoopback != _config.WfpAllowLoopback) &&
                !string.IsNullOrWhiteSpace(_lastReport?.Network.AdapterGuid))
            {
                var wfpRes = await SendHelperAsync(
                    "wfp-enable",
                    _lastReport,
                    adapterGuid: _lastReport!.Network.AdapterGuid,
                    allowLoopback: _config.WfpAllowLoopback);
                wfpNotice = wfpRes.Success ? "；WFP 出站锁已自动应用" : $"；WFP 应用失败（{wfpRes.Detail}）";
            }

            SettingsStatusText.Text = $"✓ 设置已保存至 config.json{wfpNotice}，正在重新执行完整检查…";
            SettingsStatusText.Foreground = (WpfBrush)FindResource("StatusOkBrush");
            _logger.LogAction("save-config", "ok", 0, enabled: _config.LoggingEnabled);
            await RunCheckAsync(true);
        }
        catch (Exception ex)
        {
            SettingsStatusText.Text = $"✕ 保存失败：{ex.Message}";
            SettingsStatusText.Foreground = (WpfBrush)FindResource("StatusErrorBrush");
        }
        finally
        {
            EndOperation();
        }
    }

    private void ResetSettingsButton_Click(object sender, RoutedEventArgs e)
    {
        LoadConfigToUi(new GuardianConfig());
        SettingsStatusText.Text = "已加载默认参数，点击「保存设置并重新检查」后生效。";
        SettingsStatusText.Foreground = (WpfBrush)FindResource("AccentHoverBrush");
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
        var sw = Stopwatch.StartNew();
        try
        {
            LastCheckText.Text = full
                ? "正在执行完整检查（VPN / WFP / DNS / IPv6 / WebRTC / Clash / ASN / 信誉）…"
                : "正在执行轻量网络与进程检查…";
            if (full)
            {
                _lastFullCheck = DateTimeOffset.UtcNow;
            }

            using var cycleTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(full ? 45 : 20));
            var report = await _engine.RunAsync(_config, full, cycleTimeout.Token);
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

            // Auto-sync system timezone on full check (startup & node switch, preserving original pre-override timezone)
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
        catch (OperationCanceledException)
        {
            sw.Stop();
            var timeoutMsg = $"监控循环超时（{(full ? "完整检查 >45s" : "轻量检查 >20s")}），已保持当前安全状态";
            LastCheckText.Text = timeoutMsg;
            if (_lastReport is not null)
            {
                _lastReport = _lastReport with
                {
                    Network = _lastReport.Network with
                    {
                        LastCycleDurationMs = sw.ElapsedMilliseconds,
                        LastCycleTimedOut = true
                    }
                };
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
        _checks.Clear();
        foreach (var check in report.Checks)
        {
            _checks.Add(check);
        }

        var okCount = report.Checks.Count(c => c.Status == CheckStatus.Ok);
        var warnCount = report.Checks.Count(c => c.Status == CheckStatus.Warn);
        var failCount = report.Checks.Count(c => c.Status == CheckStatus.Fail);
        var skipCount = report.Checks.Count(c => c.Status == CheckStatus.Skip);
        CheckSummaryText.Text = $"{okCount} 通过 · {warnCount} 警告 · {failCount} 失败" +
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

    private bool HasEffectiveStatus(GuardianReport report, CheckStatus status) =>
        ProtectionPolicyEvaluator.HasEffectiveUiStatus(report, status, _ignoreWebRtc);

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

    private void AppendToolOutput(string line)
    {
        var current = ToolOutputTextBox.Text;
        ToolOutputTextBox.Text = string.IsNullOrWhiteSpace(current)
            ? line
            : current + Environment.NewLine + line;
        ToolOutputTextBox.ScrollToEnd();
    }

    private async Task<HelperStatusSnapshot?> QueryHelperStatusAsync(
        string adapterGuid,
        bool allowLoopback,
        CancellationToken cancellationToken)
    {
        var result = await SendHelperAsync(
            "status",
            null,
            adapterGuid: adapterGuid,
            allowLoopback: allowLoopback);
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
            FirewallApiOk: result.FirewallApiOk ?? true,
            FirewallActiveRuleCount: result.FirewallActiveRuleCount ?? 0,
            FirewallDetail: result.FirewallDetail ?? string.Empty);
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

    private static bool RunPowerShellUserScript(string script, out string error)
    {
        error = string.Empty;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-NonInteractive");
            psi.ArgumentList.Add("-ExecutionPolicy");
            psi.ArgumentList.Add("Bypass");
            psi.ArgumentList.Add("-EncodedCommand");
            psi.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));
            using var proc = Process.Start(psi);
            if (proc is null)
            {
                error = "无法启动 PowerShell";
                return false;
            }

            var stderr = proc.StandardError.ReadToEnd();
            if (!proc.WaitForExit(10000))
            {
                try { proc.Kill(true); } catch { }
                error = "PowerShell 执行超时";
                return false;
            }

            if (proc.ExitCode != 0)
            {
                error = string.IsNullOrWhiteSpace(stderr) ? $"退出码 {proc.ExitCode}" : stderr.Trim();
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static async Task<HelperCallResult> SendHelperAsync(
        string command,
        GuardianReport? report,
        string? timezoneId = null,
        string? adapterGuid = null,
        bool allowLoopback = false,
        IReadOnlyList<string>? adapterNames = null)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", "ClaudeDesktopGuardian", PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(1500);
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
                timezoneId,
                adapterGuid,
                allowLoopback,
                adapterNames
            };
            await writer.WriteLineAsync(JsonSerializer.Serialize(request));
            var response = await reader.ReadLineAsync();
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
            var detail = success
                ? root.TryGetProperty("detail", out var detProp) && !string.IsNullOrWhiteSpace(detProp.GetString())
                    ? detProp.GetString()!
                    : root.TryGetProperty("timezoneId", out var timezone)
                        ? timezone.GetString() ?? "管理员助手已确认"
                        : "管理员助手已确认"
                : root.TryGetProperty("error", out var error)
                    ? error.GetString() ?? "管理员助手拒绝命令"
                    : "管理员助手拒绝命令";
            return new HelperCallResult(success, detail, wfpState, wfpDetail, fwApiOk, fwCount, fwDetail, helperDetail);
        }
        catch (Exception exception)
        {
            return new HelperCallResult(false, exception.Message, null);
        }
    }

    private static string FormatProbeDetail(string detail) =>
        string.IsNullOrWhiteSpace(detail) ? string.Empty : $"（{detail}）";

    private sealed record ProxyModeOption(string Key, string Label);
    private sealed record HelperCallResult(
        bool Success,
        string Detail,
        string? WfpState,
        string? WfpDetail = null,
        bool? FirewallApiOk = null,
        int? FirewallActiveRuleCount = null,
        string? FirewallDetail = null,
        string? HelperDetail = null);
}
