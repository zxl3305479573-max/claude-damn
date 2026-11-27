using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using ClaudeDesktopGuardian.Core;
using WpfMessageBox = System.Windows.MessageBox;

namespace ClaudeDesktopGuardian.App;

public partial class MainWindow
{
    private async void ReconnectHelperButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryBeginOperation("正在启动 / 重连管理员助手…"))
        {
            return;
        }

        try
        {
            var ready = await EnsureHelperAvailableAsync();
            if (ready)
            {
                _timezoneRecoveryReady = await RestoreStaleTimezoneAsync();
                await ApplySavedTcpOnlyAsync();
                AppendToolOutput("[通过] 管理员助手受限命名管道已连接就绪。");
                _logger.LogAction("reconnect-helper", "ok", 0, enabled: _config.LoggingEnabled);
                await RunCheckAsync(false);
            }
            else
            {
                var detail = string.IsNullOrWhiteSpace(_timezoneOperationError)
                    ? "未能连接到管理员助手（请确认已批准 UAC 提权）"
                    : _timezoneOperationError;
                AppendToolOutput($"[失败] {detail}");
                _logger.LogAction("reconnect-helper", "fail", 0, enabled: _config.LoggingEnabled);
            }
        }
        catch (Exception ex)
        {
            AppendToolOutput($"[失败] 重连管理员助手异常：{ex.Message}");
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

            var dnsRes = await SendHelperAsync("flush-dns", null);
            log.AppendLine(dnsRes.Success
                ? $"[通过] DNS 缓存刷新：{dnsRes.Detail}"
                : $"[警告] DNS 缓存刷新失败：{dnsRes.Detail}");

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

            var leakingAdapters = report?.Network.PublicIpv6Routes ?? Array.Empty<string>();
            if (leakingAdapters.Count > 0)
            {
                var ipv6Res = await SendHelperAsync("disable-ipv6-adapters", null, adapterNames: leakingAdapters);
                log.AppendLine(ipv6Res.Success
                    ? $"[通过] IPv6 旁路治理：{ipv6Res.Detail}"
                    : $"[警告] IPv6 旁路治理失败：{ipv6Res.Detail}");
            }
            else if (report?.Network.Observations?.GetValueOrDefault(GuardianCheckIds.Ipv6)?.Succeeded == true)
            {
                log.AppendLine("[通过] 非 VPN 网卡未发现公网/NAT64 IPv6 路由，无需修改网卡绑定");
            }
            else
            {
                log.AppendLine("[未验证] IPv6 路由采集失败，未修改网卡绑定，等待重新采集");
            }

            if (Directory.Exists(ClashInspector.FindClashVergeDir()))
            {
                var ruleFix = await _clashInspector.RepairClashVergeRulesAsync(_config, CancellationToken.None);
                log.AppendLine(ruleFix.Success
                    ? $"[通过] Clash 置顶规则：{ruleFix.Message}"
                    : $"[警告] Clash 置顶规则：{ruleFix.Message}");
            }

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

            if (_config.TcpOnlyEnabled)
            {
                var tcpOnly = await SendHelperAsync("tcp-only-enable", null);
                log.AppendLine(tcpOnly.Success ? "[通过] TCP-only 托管规则已刷新并验证旧会话退出"
                    : "[警告] TCP-only 刷新未确认：" + tcpOnly.Detail);
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

            await Task.Run(() => ClaudeLauncher.Launch(target));
            _logger.LogAction("safe-launch", "ok", 0, report?.Checks, _config.LoggingEnabled);
            LastCheckText.Text = $"已通过安全门禁并启动 Claude（绕过系统代理，由 TUN 接管；{DateTime.Now:HH:mm:ss}）";
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

    private void AppendToolOutput(string line)
    {
        var current = ToolOutputTextBox.Text;
        ToolOutputTextBox.Text = string.IsNullOrWhiteSpace(current)
            ? line
            : current + Environment.NewLine + line;
        ToolOutputTextBox.ScrollToEnd();
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
}
