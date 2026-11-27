using System.Windows;
using System.Windows.Input;

namespace ClaudeDesktopGuardian.App;

public partial class MiniStatusWindow : Window
{
    public MiniStatusWindow()
    {
        InitializeComponent();
    }

    public event Action? OpenRequested;

    public void UpdateStatus(
        string status,
        System.Windows.Media.Brush statusBrush,
        string exitIp,
        string adapter,
        string lastCheck,
        string wfpStatus = "",
        string accountSlot = "")
    {
        StatusText.Text = status;
        StatusText.Foreground = statusBrush;
        ExitIpText.Text = exitIp;
        AdapterText.Text = adapter;
        WfpStatusText.Text = string.IsNullOrWhiteSpace(wfpStatus) ? "WFP：未启用" : wfpStatus;
        AccountSlotText.Text = string.IsNullOrWhiteSpace(accountSlot) ? "槽位：未绑定" : accountSlot;
        LastCheckText.Text = lastCheck;
    }

    private void OpenButton_Click(object sender, RoutedEventArgs e)
    {
        OpenRequested?.Invoke();
    }

    private void RootBorder_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            OpenRequested?.Invoke();
        }
    }
}
