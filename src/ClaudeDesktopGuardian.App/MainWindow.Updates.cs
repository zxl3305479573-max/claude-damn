using System.Diagnostics;
using System.IO;
using System.Windows;
using ClaudeDesktopGuardian.Core;
using WpfMessageBox = System.Windows.MessageBox;

namespace ClaudeDesktopGuardian.App;

public partial class MainWindow
{
    private async void UpdateButton_Click(object sender, RoutedEventArgs e)
    {
        if (_updateCheckInProgress || _updateInstallInProgress)
        {
            return;
        }

        if (_operationInProgress)
        {
            WpfMessageBox.Show(
                "当前正在执行其他操作，请完成后再检查或安装更新。",
                "暂不可更新",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        if (_availableUpdate is null)
        {
            await CheckForUpdatesAsync(true);
            return;
        }

        var choice = WpfMessageBox.Show(
            $"发现 claude-damn v{_availableUpdate.Version}。现在下载并安装吗？",
            "发现更新",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);
        if (choice == MessageBoxResult.Yes)
        {
            await InstallUpdateAsync(_availableUpdate);
        }
    }

    private async Task CheckForUpdatesAsync(bool showErrors)
    {
        if (_updateCheckInProgress || _updateInstallInProgress || _exiting || _allowExit)
        {
            return;
        }

        _updateCheckInProgress = true;
        UpdateButton.IsEnabled = false;
        UpdateStatusText.Text = "正在检查 GitHub 更新…";
        try
        {
            var version = GetInstalledVersion();
            _availableUpdate = await _updateService.CheckAsync(version);
            if (_availableUpdate is null)
            {
                UpdateStatusText.Text = $"当前已是最新版本 v{version}";
                UpdateButton.Content = "检查更新";
            }
            else
            {
                UpdateStatusText.Text = $"发现新版本 v{_availableUpdate.Version}";
                UpdateButton.Content = $"更新到 v{_availableUpdate.Version}";
            }
        }
        catch (Exception ex)
        {
            _availableUpdate = null;
            UpdateStatusText.Text = "更新检查失败，可稍后重试";
            UpdateButton.Content = "检查更新";
            if (showErrors)
            {
                WpfMessageBox.Show(
                    $"检查更新失败：{ex.Message}",
                    "更新检查失败",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }
        finally
        {
            _updateCheckInProgress = false;
            UpdateButton.IsEnabled = !_operationInProgress && !_exiting && !_allowExit;
        }
    }

    private async Task InstallUpdateAsync(GuardianUpdate update)
    {
        _updateInstallInProgress = true;
        SetOperationControlsEnabled(false);
        var packageDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ClaudeDesktopGuardian",
            "updates",
            Guid.NewGuid().ToString("N"));
        var packagePath = Path.Combine(packageDirectory, update.PackageName);
        var readyPath = Path.Combine(packageDirectory, "updater-ready.txt");
        Process? updater = null;

        try
        {
            Directory.CreateDirectory(packageDirectory);
            UpdateStatusText.Text = $"正在下载并校验 v{update.Version}…";
            var hash = await _updateService.DownloadAndVerifyAsync(update, packagePath);

            var updaterPath = Path.Combine(AppContext.BaseDirectory, "apply-update.ps1");
            if (!File.Exists(updaterPath))
            {
                throw new FileNotFoundException("安装目录缺少 OTA 更新器，请重新安装当前版本。", updaterPath);
            }

            var startInfo = new ProcessStartInfo("powershell.exe")
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = AppContext.BaseDirectory
            };
            startInfo.ArgumentList.Add("-NoProfile");
            startInfo.ArgumentList.Add("-ExecutionPolicy");
            startInfo.ArgumentList.Add("Bypass");
            startInfo.ArgumentList.Add("-File");
            startInfo.ArgumentList.Add(updaterPath);
            startInfo.ArgumentList.Add("-PackagePath");
            startInfo.ArgumentList.Add(packagePath);
            startInfo.ArgumentList.Add("-ExpectedSha256");
            startInfo.ArgumentList.Add(hash);
            startInfo.ArgumentList.Add("-ReadyPath");
            startInfo.ArgumentList.Add(readyPath);
            startInfo.ArgumentList.Add("-ParentProcessId");
            startInfo.ArgumentList.Add(Environment.ProcessId.ToString());

            updater = Process.Start(startInfo) ?? throw new InvalidOperationException("无法启动管理员更新器。");
            UpdateStatusText.Text = "请在系统权限提示中确认更新…";
            await WaitForUpdaterReadyAsync(updater, readyPath);

            UpdateStatusText.Text = "更新包已验证，正在安全退出并切换版本…";
            ExitFromTray();
            await _closedSignal.Task.WaitAsync(TimeSpan.FromMinutes(4));
        }
        catch (Exception ex)
        {
            UpdateStatusText.Text = "更新未完成，当前版本保持不变";
            UpdateButton.IsEnabled = !_operationInProgress && !_exiting && !_allowExit;
            WpfMessageBox.Show(
                $"安装更新失败：{ex.Message}",
                "更新失败",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        finally
        {
            if (updater is null || updater.HasExited)
            {
                try
                {
                    if (File.Exists(packagePath))
                    {
                        File.Delete(packagePath);
                    }

                    if (Directory.Exists(packageDirectory))
                    {
                        Directory.Delete(packageDirectory, true);
                    }
                }
                catch
                {
                }
            }

            _updateInstallInProgress = false;
            if (!_allowExit && !_exiting)
            {
                SetOperationControlsEnabled(true);
            }
        }
    }

    private static async Task WaitForUpdaterReadyAsync(Process updater, string readyPath)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(90);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (File.Exists(readyPath))
            {
                return;
            }

            if (updater.HasExited)
            {
                throw new InvalidOperationException(
                    "管理员更新器未能启动，请确认权限提示已获准后重试。");
            }

            await Task.Delay(250);
        }

        throw new TimeoutException("管理员更新器启动超时，更新未开始。");
    }

    private static string GetInstalledVersion()
    {
        var version = typeof(MainWindow).Assembly.GetName().Version ?? new Version(1, 0, 0);
        return $"{version.Major}.{version.Minor}.{Math.Max(0, version.Build)}";
    }
}
