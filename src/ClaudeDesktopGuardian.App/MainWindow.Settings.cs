using System.Globalization;
using System.Windows;
using ClaudeDesktopGuardian.Core;
using WpfBrush = System.Windows.Media.Brush;
using WpfCheckBox = System.Windows.Controls.CheckBox;

namespace ClaudeDesktopGuardian.App;

public partial class MainWindow
{
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

    private void MainTabControl_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (!ReferenceEquals(e.OriginalSource, MainTabControl) || _operationInProgress)
        {
            return;
        }

        SyncExternalConfigIfChanged();
    }

    private void LoadConfigToUi(GuardianConfig cfg, bool updateBaseline = true)
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
        TcpOnlyCheckBox.IsChecked = cfg.TcpOnlyEnabled;
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

        if (updateBaseline)
        {
            _uiBaselineConfig = cfg;
            _settingsResetPending = false;
        }
    }

    private bool HasUnsavedSettingsEdits(GuardianConfig baseline)
    {
        if (_settingsResetPending)
        {
            return true;
        }

        if (!string.Equals(ProxyClientModeCombo.SelectedValue?.ToString(), ProxyClientModes.Normalize(baseline.ProxyClientMode), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(WebRtcPolicyCombo.SelectedValue?.ToString(), WebRtcPolicies.Normalize(baseline.WebRtcPolicy), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(ExpectedCountryBox.Text, baseline.ExpectedExitCountry ?? string.Empty, StringComparison.Ordinal) ||
            !string.Equals(ExpectedIpBox.Text, baseline.ExpectedExitIp ?? string.Empty, StringComparison.Ordinal) ||
            !string.Equals(ExpectedLocaleBox.Text, baseline.ExpectedLocale ?? string.Empty, StringComparison.Ordinal) ||
            !string.Equals(VpnPatternBox.Text, baseline.VpnAdapterPattern ?? string.Empty, StringComparison.Ordinal) ||
            !string.Equals(FlClashControllerBox.Text, baseline.FlClashController ?? string.Empty, StringComparison.Ordinal) ||
            !string.Equals(ClashProxyGroupBox.Text, baseline.ClashProxyGroup, StringComparison.Ordinal) ||
            !string.Equals(LightIntervalBox.Text, baseline.LightIntervalSeconds.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal) ||
            !string.Equals(FullIntervalBox.Text, baseline.FullIntervalMinutes.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal) ||
            (WfpStrictCheckBox.IsChecked == true) != baseline.WfpStrictEnabled ||
            (WfpLoopbackCheckBox.IsChecked == true) != baseline.WfpAllowLoopback ||
            (TcpOnlyCheckBox.IsChecked == true) != baseline.TcpOnlyEnabled ||
            (AllowOptionalFailuresCheckBox.IsChecked == true) != baseline.AllowOptionalFailures ||
            (LoggingEnabledCheckBox.IsChecked == true) != baseline.LoggingEnabled ||
            !string.Equals(IpRepUrlBox.Text, baseline.IpReputation?.Url ?? string.Empty, StringComparison.Ordinal) ||
            !string.IsNullOrEmpty(IpRepKeyBox.Password) ||
            !string.Equals(IpRepThresholdBox.Text, (baseline.IpReputation?.Threshold ?? 25).ToString("0.#", CultureInfo.InvariantCulture), StringComparison.Ordinal) ||
            !string.Equals(IpRepCacheDaysBox.Text, (baseline.IpReputation?.CacheDays ?? 7).ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal))
        {
            return true;
        }

        foreach (var (id, cb) in _optionalCheckBoxes)
        {
            if ((cb.IsChecked == true) != !baseline.IsCheckDisabled(id))
            {
                return true;
            }
        }

        return false;
    }

    private bool SyncExternalConfigIfChanged()
    {
        if (!_configStore.TryReloadIfChanged(ref _configFingerprint, out var reloaded))
        {
            return false;
        }

        _config = reloaded;
        if (_timer is not null)
        {
            _timer.Interval = TimeSpan.FromSeconds(_config.LightIntervalSeconds);
        }

        if (!HasUnsavedSettingsEdits(_uiBaselineConfig))
        {
            LoadConfigToUi(_config, updateBaseline: true);
        }

        _fullCheckPending = true;
        return true;
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

            var latestDisk = _configStore.Load(out _configFingerprint);
            _config = latestDisk;
            var previousWfpStrict = latestDisk.WfpStrictEnabled;
            var previousWfpLoopback = latestDisk.WfpAllowLoopback;

            var uiCandidate = _uiBaselineConfig with
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
                TcpOnlyEnabled = TcpOnlyCheckBox.IsChecked == true,
                AllowOptionalFailures = AllowOptionalFailuresCheckBox.IsChecked == true,
                LoggingEnabled = LoggingEnabledCheckBox.IsChecked == true,
                DisabledOptionalChecks = disabledOptional,
                IpReputation = ipRep
            };

            var candidate = _settingsResetPending
                ? GuardianConfigStore.SanitizeAndValidate(uiCandidate, throwOnError: true)
                : MergeUiEditsOverLatestConfig(_uiBaselineConfig, latestDisk, uiCandidate);

            var (savedConfig, tcpOnlyNotice) = await SaveConfigWithTcpOnlyTransitionAsync(
                latestDisk,
                candidate,
                _configStore,
                cmd => SendHelperAsync(cmd, null));
            _config = savedConfig;
            _configFingerprint = _configStore.CaptureFingerprint();
            _timer.Interval = TimeSpan.FromSeconds(_config.LightIntervalSeconds);
            LoadConfigToUi(_config, updateBaseline: true);
            if (!string.IsNullOrEmpty(tcpOnlyNotice) && tcpOnlyNotice.Contains("未确认", StringComparison.Ordinal))
            {
                AppendToolOutput("[警告] " + tcpOnlyNotice.TrimStart('；'));
            }

            var wfpNotice = string.Empty;
            if (_config.WfpStrictEnabled &&
                (!previousWfpStrict || previousWfpLoopback != _config.WfpAllowLoopback))
            {
                var currentReport = await RunCheckAsync(false) ?? _lastReport;
                if (!string.IsNullOrWhiteSpace(currentReport?.Network.AdapterGuid))
                {
                    var wfpRes = await SendHelperAsync(
                        "wfp-enable",
                        currentReport,
                        adapterGuid: currentReport!.Network.AdapterGuid,
                        allowLoopback: _config.WfpAllowLoopback);
                    wfpNotice = wfpRes.Success ? "；WFP 出站锁已自动应用" : $"；WFP 应用失败（{wfpRes.Detail}）";
                }
            }

            SettingsStatusText.Text = $"✓ 设置已保存至 config.json{tcpOnlyNotice}{wfpNotice}，正在重新执行完整检查…";
            SettingsStatusText.Foreground = (WpfBrush)FindResource("StatusOkBrush");
            _logger.LogAction("save-config", "ok", 0, enabled: _config.LoggingEnabled);
            await RunCheckAsync(true);
        }
        catch (Exception ex)
        {
            TcpOnlyCheckBox.IsChecked = _config.TcpOnlyEnabled;
            SettingsStatusText.Text = $"✕ 保存失败：{ex.Message}";
            SettingsStatusText.Foreground = (WpfBrush)FindResource("StatusErrorBrush");
        }
        finally
        {
            EndOperation();
        }
    }

    internal static GuardianConfig MergeUiEditsOverLatestConfig(
        GuardianConfig uiBaseline,
        GuardianConfig latestDisk,
        GuardianConfig uiCandidate)
    {
        var baseline = GuardianConfigStore.SanitizeAndValidate(uiBaseline, throwOnError: false);
        var disk = GuardianConfigStore.SanitizeAndValidate(latestDisk, throwOnError: false);
        var candidate = GuardianConfigStore.SanitizeAndValidate(uiCandidate, throwOnError: true);

        var baselineDisabled = new HashSet<string>(
            baseline.DisabledOptionalChecks ?? Array.Empty<string>(),
            StringComparer.OrdinalIgnoreCase);
        var candidateDisabled = new HashSet<string>(
            candidate.DisabledOptionalChecks ?? Array.Empty<string>(),
            StringComparer.OrdinalIgnoreCase);
        var disabledChanged = !baselineDisabled.SetEquals(candidateDisabled);

        return disk with
        {
            ProxyClientMode = !string.Equals(candidate.ProxyClientMode, baseline.ProxyClientMode, StringComparison.OrdinalIgnoreCase)
                ? candidate.ProxyClientMode
                : disk.ProxyClientMode,
            WebRtcPolicy = !string.Equals(candidate.WebRtcPolicy, baseline.WebRtcPolicy, StringComparison.OrdinalIgnoreCase)
                ? candidate.WebRtcPolicy
                : disk.WebRtcPolicy,
            ExpectedExitCountry = !string.Equals(candidate.ExpectedExitCountry, baseline.ExpectedExitCountry, StringComparison.OrdinalIgnoreCase)
                ? candidate.ExpectedExitCountry
                : disk.ExpectedExitCountry,
            ExpectedExitIp = !string.Equals(candidate.ExpectedExitIp, baseline.ExpectedExitIp, StringComparison.OrdinalIgnoreCase)
                ? candidate.ExpectedExitIp
                : disk.ExpectedExitIp,
            ExpectedLocale = !string.Equals(candidate.ExpectedLocale, baseline.ExpectedLocale, StringComparison.OrdinalIgnoreCase)
                ? candidate.ExpectedLocale
                : disk.ExpectedLocale,
            VpnAdapterPattern = !string.Equals(candidate.VpnAdapterPattern, baseline.VpnAdapterPattern, StringComparison.Ordinal)
                ? candidate.VpnAdapterPattern
                : disk.VpnAdapterPattern,
            FlClashController = !string.Equals(candidate.FlClashController, baseline.FlClashController, StringComparison.OrdinalIgnoreCase)
                ? candidate.FlClashController
                : disk.FlClashController,
            ClashProxyGroup = !string.Equals(candidate.ClashProxyGroup, baseline.ClashProxyGroup, StringComparison.Ordinal)
                ? candidate.ClashProxyGroup
                : disk.ClashProxyGroup,
            LightIntervalSeconds = candidate.LightIntervalSeconds != baseline.LightIntervalSeconds
                ? candidate.LightIntervalSeconds
                : disk.LightIntervalSeconds,
            FullIntervalMinutes = candidate.FullIntervalMinutes != baseline.FullIntervalMinutes
                ? candidate.FullIntervalMinutes
                : disk.FullIntervalMinutes,
            WfpStrictEnabled = candidate.WfpStrictEnabled != baseline.WfpStrictEnabled
                ? candidate.WfpStrictEnabled
                : disk.WfpStrictEnabled,
            WfpAllowLoopback = candidate.WfpAllowLoopback != baseline.WfpAllowLoopback
                ? candidate.WfpAllowLoopback
                : disk.WfpAllowLoopback,
            TcpOnlyEnabled = candidate.TcpOnlyEnabled != baseline.TcpOnlyEnabled
                ? candidate.TcpOnlyEnabled
                : disk.TcpOnlyEnabled,
            AllowOptionalFailures = candidate.AllowOptionalFailures != baseline.AllowOptionalFailures
                ? candidate.AllowOptionalFailures
                : disk.AllowOptionalFailures,
            LoggingEnabled = candidate.LoggingEnabled != baseline.LoggingEnabled
                ? candidate.LoggingEnabled
                : disk.LoggingEnabled,
            DisabledOptionalChecks = disabledChanged
                ? candidate.DisabledOptionalChecks
                : disk.DisabledOptionalChecks,
            IpReputation = IpReputationChangedInUi(baseline.IpReputation, candidate.IpReputation)
                ? candidate.IpReputation
                : disk.IpReputation
        };
    }

    private static bool IpReputationChangedInUi(IpReputationConfig? baseline, IpReputationConfig? candidate)
    {
        if (baseline is null && candidate is null)
        {
            return false;
        }

        if (baseline is null || candidate is null)
        {
            return true;
        }

        return !string.Equals(baseline.Url, candidate.Url, StringComparison.Ordinal) ||
               !string.IsNullOrEmpty(candidate.Key) ||
               Math.Abs(baseline.Threshold - candidate.Threshold) > 1e-9 ||
               baseline.CacheDays != candidate.CacheDays;
    }

    internal static async Task<(GuardianConfig SavedConfig, string TcpOnlyNotice)> SaveConfigWithTcpOnlyTransitionAsync(
        GuardianConfig previousConfig,
        GuardianConfig candidateConfig,
        GuardianConfigStore configStore,
        Func<string, Task<HelperCallResult>> sendHelperAsync)
    {
        var validated = GuardianConfigStore.SanitizeAndValidate(candidateConfig, throwOnError: true);

        if (previousConfig.TcpOnlyEnabled && !validated.TcpOnlyEnabled)
        {
            var disableRes = await sendHelperAsync("tcp-only-disable");
            if (!disableRes.Success)
            {
                throw new InvalidOperationException(
                    $"TCP-only 托管规则未确认清理，已保留启用状态（{disableRes.Detail}）；请启动或重连管理员助手后重试");
            }

            var disabledSaved = configStore.Save(validated, preserveExistingApiKeyIfEmpty: true);
            return (disabledSaved, "；TCP-only 规则已清理");
        }

        var saved = configStore.Save(validated, preserveExistingApiKeyIfEmpty: true);
        if (!previousConfig.TcpOnlyEnabled && saved.TcpOnlyEnabled)
        {
            var enableRes = await sendHelperAsync("tcp-only-enable");
            var notice = enableRes.Success
                ? "；TCP-only 规则已应用"
                : $"；TCP-only 未确认（{enableRes.Detail}）";
            return (saved, notice);
        }

        return (saved, string.Empty);
    }

    private void ResetSettingsButton_Click(object sender, RoutedEventArgs e)
    {
        _settingsResetPending = true;
        LoadConfigToUi(GuardianConfig.CreateDefault(), updateBaseline: false);
        SettingsStatusText.Text = "已加载默认参数，点击「保存设置并重新检查」后生效。";
        SettingsStatusText.Foreground = (WpfBrush)FindResource("AccentHoverBrush");
    }
}
