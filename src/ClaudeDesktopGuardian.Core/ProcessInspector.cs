using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace ClaudeDesktopGuardian.Core;

internal readonly record struct RawProcessEntry(int ProcessId, int ParentProcessId, string Name);

public sealed class WindowsProcessInspector : IProcessInspector
{
    public IReadOnlyList<ProcessInfo> FindClaudeProcessTree()
    {
        var rawEntries = ProcessSnapshot.ReadRawEntries();
        if (rawEntries.Count == 0)
        {
            return Array.Empty<ProcessInfo>();
        }

        var currentSid = OperatingSystem.IsWindows()
            ? WindowsIdentity.GetCurrent().User?.Value ?? string.Empty
            : string.Empty;
        return FilterClaudeTree(rawEntries, ProcessSnapshot.InspectProcess, currentSid);
    }

    internal static IReadOnlyList<ProcessInfo> FilterClaudeTree(
        IReadOnlyList<RawProcessEntry> entries,
        Func<int, (string Path, string Sid)> inspector,
        string currentSid)
    {
        // Phase 1: Pure in-memory filter on process name + parent-child graph (zero OpenProcess syscalls on unrelated PIDs)
        var candidateRoots = new List<RawProcessEntry>();
        foreach (var entry in entries)
        {
            if (entry.Name.Equals("Claude", StringComparison.OrdinalIgnoreCase) ||
                entry.Name.Equals("Claude.exe", StringComparison.OrdinalIgnoreCase))
            {
                candidateRoots.Add(entry);
            }
        }

        if (candidateRoots.Count == 0)
        {
            return Array.Empty<ProcessInfo>();
        }

        var verifiedRootIds = new HashSet<int>();
        var inspectedCache = new Dictionary<int, (string Path, string Sid)>();
        foreach (var root in candidateRoots)
        {
            var inspected = inspector(root.ProcessId);
            inspectedCache[root.ProcessId] = inspected;
            if (IsClaudePath(inspected.Path) &&
                (string.IsNullOrEmpty(inspected.Sid) ||
                 string.IsNullOrEmpty(currentSid) ||
                 string.Equals(inspected.Sid, currentSid, StringComparison.OrdinalIgnoreCase)))
            {
                verifiedRootIds.Add(root.ProcessId);
            }
        }

        if (verifiedRootIds.Count == 0)
        {
            return Array.Empty<ProcessInfo>();
        }

        var treeIds = new HashSet<int>(verifiedRootIds);
        var changed = true;
        while (changed)
        {
            changed = false;
            foreach (var entry in entries)
            {
                if (treeIds.Contains(entry.ParentProcessId) && treeIds.Add(entry.ProcessId))
                {
                    changed = true;
                }
            }
        }

        // Phase 2: Inspect only the small handful of processes belonging to the verified Claude process tree
        var result = new List<ProcessInfo>(treeIds.Count);
        foreach (var entry in entries)
        {
            if (!treeIds.Contains(entry.ProcessId))
            {
                continue;
            }

            if (!inspectedCache.TryGetValue(entry.ProcessId, out var inspected))
            {
                inspected = inspector(entry.ProcessId);
                inspectedCache[entry.ProcessId] = inspected;
            }

            if (string.IsNullOrEmpty(inspected.Sid) ||
                string.IsNullOrEmpty(currentSid) ||
                string.Equals(inspected.Sid, currentSid, StringComparison.OrdinalIgnoreCase))
            {
                result.Add(new ProcessInfo(entry.ProcessId, entry.ParentProcessId, entry.Name, inspected.Path, inspected.Sid));
            }
        }

        return result;
    }

    internal static IReadOnlyList<ProcessInfo> FindCurrentUserCliProcesses()
    {
        if (!OperatingSystem.IsWindows())
        {
            return Array.Empty<ProcessInfo>();
        }

        var rawEntries = ProcessSnapshot.ReadRawEntries();
        var currentSid = WindowsIdentity.GetCurrent().User?.Value ?? string.Empty;
        var result = new List<ProcessInfo>();

        foreach (var entry in rawEntries)
        {
            if (!entry.Name.Equals("claude", StringComparison.OrdinalIgnoreCase) &&
                !entry.Name.Equals("claude.exe", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var (path, sid) = ProcessSnapshot.InspectProcess(entry.ProcessId);
            if (IsDesktopElectronPath(path))
            {
                continue;
            }

            if (string.IsNullOrEmpty(sid) || string.Equals(sid, currentSid, StringComparison.OrdinalIgnoreCase))
            {
                result.Add(new ProcessInfo(entry.ProcessId, entry.ParentProcessId, entry.Name, path, sid));
            }
        }

        return result;
    }

    internal static bool IsDesktopElectronPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var normalized = path.Replace('/', '\\');
        return normalized.Contains("\\AnthropicClaude\\", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("\\Programs\\Claude\\", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("\\WindowsApps\\Claude_", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsClaudePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return true;
        }

        var normalized = path.Replace('/', '\\');
        return normalized.Contains("\\AnthropicClaude\\", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("\\Programs\\Claude\\", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("\\Claude\\", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("\\WindowsApps\\Claude_", StringComparison.OrdinalIgnoreCase);
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
    public static IReadOnlyList<RawProcessEntry> ReadRawEntries()
    {
        if (!OperatingSystem.IsWindows())
        {
            return Array.Empty<RawProcessEntry>();
        }

        var result = new List<RawProcessEntry>();
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
            result.Add(new RawProcessEntry(
                (int)entry.th32ProcessID,
                (int)entry.th32ParentProcessID,
                entry.szExeFile.TrimEnd('\0')));
        }
        while (NativeMethods.Process32Next(snapshot, ref entry));

        return result;
    }

    /// <summary>
    /// Opens a single PROCESS_QUERY_LIMITED_INFORMATION handle to query both the full image path
    /// (via QueryFullProcessImageNameW, avoiding MainModule/EnumProcessModulesEx overhead) and user SID.
    /// </summary>
    public static (string Path, string Sid) InspectProcess(int processId)
    {
        if (!OperatingSystem.IsWindows() || processId <= 4)
        {
            return (string.Empty, string.Empty);
        }

        try
        {
            using var handle = NativeMethods.OpenProcess(
                NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                (uint)processId);
            if (handle.IsInvalid)
            {
                return (string.Empty, string.Empty);
            }

            var path = QueryImagePath(handle);
            var sid = QueryProcessSid(handle);
            return (path, sid);
        }
        catch
        {
            return (string.Empty, string.Empty);
        }
    }

    private static string QueryImagePath(SafeProcessHandle handle)
    {
        var capacity = 1024;
        var buffer = new StringBuilder(capacity);
        return NativeMethods.QueryFullProcessImageName(handle, 0, buffer, ref capacity)
            ? buffer.ToString(0, capacity)
            : string.Empty;
    }

    private static string QueryProcessSid(SafeProcessHandle handle)
    {
        if (!NativeMethods.OpenProcessToken(handle, NativeMethods.TOKEN_QUERY, out var token))
        {
            return string.Empty;
        }

        using (token)
        {
            var length = 0;
            NativeMethods.GetTokenInformation(token, 1, IntPtr.Zero, 0, out length);
            if (length <= 0)
            {
                return string.Empty;
            }

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

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool QueryFullProcessImageName(
        SafeProcessHandle process,
        uint flags,
        StringBuilder exeName,
        ref int size);

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
