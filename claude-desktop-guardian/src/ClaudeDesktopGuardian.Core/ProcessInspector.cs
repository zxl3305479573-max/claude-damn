using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ClaudeDesktopGuardian.Core;

public sealed class WindowsProcessInspector : IProcessInspector
{
    public IReadOnlyList<ProcessInfo> FindClaudeProcessTree()
    {
        var entries = ProcessSnapshot.Read();
        var roots = entries
            .Where(entry =>
                entry.Name.Equals("Claude", StringComparison.OrdinalIgnoreCase) ||
                entry.Name.Equals("Claude.exe", StringComparison.OrdinalIgnoreCase))
            .Where(IsClaudePath)
            .ToArray();

        var ids = new HashSet<int>(roots.Select(root => root.ProcessId));
        var changed = true;
        while (changed)
        {
            changed = false;
            foreach (var entry in entries)
            {
                if (ids.Contains(entry.ParentProcessId) && ids.Add(entry.ProcessId))
                {
                    changed = true;
                }
            }
        }

        var currentSid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
        return entries
            .Where(entry => ids.Contains(entry.ProcessId))
            .Where(entry => string.IsNullOrEmpty(entry.UserSid) || entry.UserSid == currentSid)
            .ToArray();
    }

    private static bool IsClaudePath(ProcessInfo entry)
    {
        if (string.IsNullOrWhiteSpace(entry.Path))
        {
            return true;
        }

        var path = entry.Path.Replace('/', '\\');
        return path.Contains("\\AnthropicClaude\\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("\\Programs\\Claude\\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("\\Claude\\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("\\WindowsApps\\Claude_", StringComparison.OrdinalIgnoreCase);
    }
}

public sealed class WindowsClaudeProcessMonitor : IDisposable
{
    private ManagementEventWatcher? _startWatcher;
    private ManagementEventWatcher? _stopWatcher;

    public event EventHandler? Changed;

    public bool IsRunning { get; private set; }

    public string? StartError { get; private set; }

    public bool TryStart()
    {
        if (IsRunning)
        {
            return true;
        }

        if (!OperatingSystem.IsWindows())
        {
            StartError = "当前系统不是 Windows";
            return false;
        }

        try
        {
            _startWatcher = CreateWatcher("Win32_ProcessStartTrace");
            _stopWatcher = CreateWatcher("Win32_ProcessStopTrace");
            _startWatcher.EventArrived += OnProcessEvent;
            _stopWatcher.EventArrived += OnProcessEvent;
            _startWatcher.Start();
            _stopWatcher.Start();
            IsRunning = true;
            StartError = null;
            return true;
        }
        catch (Exception exception)
        {
            StartError = exception.Message;
            DisposeWatchers();
            return false;
        }
    }

    public void Dispose()
    {
        DisposeWatchers();
        GC.SuppressFinalize(this);
    }

    private static ManagementEventWatcher CreateWatcher(string traceClass) =>
        new(new WqlEventQuery(
            $"SELECT ProcessID, ProcessName FROM {traceClass} " +
            "WHERE ProcessName = 'Claude.exe' OR " +
            "ProcessName = 'Claude' OR " +
            "ProcessName = 'Claude Desktop.exe'"));

    private void OnProcessEvent(object sender, EventArrivedEventArgs e) =>
        Changed?.Invoke(this, EventArgs.Empty);

    private void DisposeWatchers()
    {
        foreach (var watcher in new[] { _startWatcher, _stopWatcher })
        {
            if (watcher is null)
            {
                continue;
            }

            watcher.EventArrived -= OnProcessEvent;
            try
            {
                watcher.Stop();
            }
            catch
            {
            }

            watcher.Dispose();
        }

        _startWatcher = null;
        _stopWatcher = null;
        IsRunning = false;
    }
}

internal static class ProcessSnapshot
{
    public static IReadOnlyList<ProcessInfo> Read()
    {
        if (!OperatingSystem.IsWindows())
        {
            return Array.Empty<ProcessInfo>();
        }

        var result = new List<ProcessInfo>();
        using var snapshot = NativeMethods.CreateToolhelp32Snapshot(
            NativeMethods.TH32CS_SNAPPROCESS,
            0);

        if (snapshot.IsInvalid)
        {
            return result;
        }

        var entry = new NativeMethods.PROCESSENTRY32
        {
            dwSize = (uint)Marshal.SizeOf<NativeMethods.PROCESSENTRY32>()
        };

        if (!NativeMethods.Process32First(snapshot, ref entry))
        {
            return result;
        }

        do
        {
            var processId = (int)entry.th32ProcessID;
            var name = entry.szExeFile.TrimEnd('\0');
            var path = TryGetPath(processId);
            var sid = TryGetSid(processId);
            result.Add(new ProcessInfo(processId, (int)entry.th32ParentProcessID, name, path, sid));
        }
        while (NativeMethods.Process32Next(snapshot, ref entry));

        return result;
    }

    private static string TryGetPath(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.MainModule?.FileName ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string TryGetSid(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            using var handle = NativeMethods.OpenProcess(
                NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                (uint)process.Id);
            if (handle.IsInvalid ||
                !NativeMethods.OpenProcessToken(
                    handle,
                    NativeMethods.TOKEN_QUERY,
                    out var token))
            {
                return string.Empty;
            }

            using (token)
            {
                var length = 0;
                NativeMethods.GetTokenInformation(token, 1, IntPtr.Zero, 0, out length);
                var buffer = Marshal.AllocHGlobal(length);
                try
                {
                    if (!NativeMethods.GetTokenInformation(token, 1, buffer, length, out _))
                    {
                        return string.Empty;
                    }

                    var tokenUser = Marshal.PtrToStructure<NativeMethods.TOKEN_USER>(buffer);
                    return new SecurityIdentifier(tokenUser.User.Sid).Value;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }
        catch
        {
            return string.Empty;
        }
    }
}

internal static class NativeMethods
{
    public const uint TH32CS_SNAPPROCESS = 0x00000002;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint TOKEN_QUERY = 0x0008;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern SafeSnapshotHandle CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Process32First(SafeSnapshotHandle snapshot, ref PROCESSENTRY32 entry);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Process32Next(SafeSnapshotHandle snapshot, ref PROCESSENTRY32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern SafeProcessHandle OpenProcess(
        uint access,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(
        SafeProcessHandle process,
        uint access,
        out SafeTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetTokenInformation(
        SafeTokenHandle token,
        int tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }
}

internal sealed class SafeProcessHandle : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeProcessHandle() : base(true)
    {
    }

    protected override bool ReleaseHandle() => CloseHandle(handle);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}

internal sealed class SafeTokenHandle : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeTokenHandle() : base(true)
    {
    }

    protected override bool ReleaseHandle() => CloseHandle(handle);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}

internal sealed class SafeSnapshotHandle : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeSnapshotHandle() : base(true)
    {
    }

    protected override bool ReleaseHandle() => CloseHandle(handle);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}

