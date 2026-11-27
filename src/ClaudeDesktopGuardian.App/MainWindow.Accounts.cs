using System.Diagnostics;
using ClaudeDesktopGuardian.Core;
using WpfBrush = System.Windows.Media.Brush;
using WpfButton = System.Windows.Controls.Button;
using WpfComboBoxItem = System.Windows.Controls.ComboBoxItem;

namespace ClaudeDesktopGuardian.App;

public partial class MainWindow
{
    private void RefreshAccountsButton_Click(object sender, System.Windows.RoutedEventArgs e)
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

    private async void SwitchAccountButton_Click(object sender, System.Windows.RoutedEventArgs e)
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

    private void SaveKeepPathsButton_Click(object sender, System.Windows.RoutedEventArgs e)
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

    private async void ExportSnapshotButton_Click(object sender, System.Windows.RoutedEventArgs e)
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

    private async void ImportSnapshotButton_Click(object sender, System.Windows.RoutedEventArgs e)
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
}
