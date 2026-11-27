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
            var previousTcpOnly = _config.TcpOnlyEnabled;

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
                TcpOnlyEnabled = TcpOnlyCheckBox.IsChecked == true,
                AllowOptionalFailures = AllowOptionalFailuresCheckBox.IsChecked == true,
                LoggingEnabled = LoggingEnabledCheckBox.IsChecked == true,
                DisabledOptionalChecks = disabledOptional,
                IpReputation = ipRep
            };

            _config = _configStore.Save(candidate, preserveExistingApiKeyIfEmpty: true);
            _timer.Interval = TimeSpan.FromSeconds(_config.LightIntervalSeconds);
            LoadConfigToUi(_config);

            var tcpOnlyNotice = string.Empty;
            if (previousTcpOnly != _config.TcpOnlyEnabled)
            {
                var tcpRes = await ApplySavedTcpOnlyAsync();
                tcpOnlyNotice = tcpRes.Success
                    ? (_config.TcpOnlyEnabled ? "；TCP-only 规则已应用" : "；TCP-only 规则已清理")
                    : $"；TCP-only 未确认（{tcpRes.Detail}）";
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
}
