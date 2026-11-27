using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ClaudeDesktopGuardian.Core;

public static class ClaudeLauncher
{
    public const string DirectConnectionArgument = "--no-proxy-server";
    private const string AppsFolderPrefix = "shell:AppsFolder\\";

    public static void Launch(string target)
    {
        if (new WindowsProcessInspector().FindClaudeProcessTree().Count > 0)
        {
            throw new InvalidOperationException("请先完全退出已有 Claude，再从 Guardian 安全启动，使仅走 TUN 的启动参数生效。");
        }

        if (target.StartsWith(AppsFolderPrefix, StringComparison.OrdinalIgnoreCase))
        {
            var managerType = Type.GetTypeFromCLSID(new Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C"), throwOnError: true)!;
            var manager = (IApplicationActivationManager)Activator.CreateInstance(managerType)!;
            try
            {
                var result = manager.ActivateApplication(target[AppsFolderPrefix.Length..], DirectConnectionArgument, 0, out _);
                Marshal.ThrowExceptionForHR(result);
            }
            finally
            {
                Marshal.FinalReleaseComObject(manager);
            }
            return;
        }

        using var process = Process.Start(CreateStartInfo(target))
            ?? throw new InvalidOperationException("未能启动 Claude Desktop。");
    }

    public static ProcessStartInfo CreateStartInfo(string executablePath)
    {
        if (!Path.IsPathFullyQualified(executablePath) ||
            !string.Equals(Path.GetFileName(executablePath), "Claude.exe", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("必须指定 Claude.exe 的绝对路径。", nameof(executablePath));
        }

        var startInfo = new ProcessStartInfo(executablePath) { UseShellExecute = false };
        startInfo.ArgumentList.Add(DirectConnectionArgument);
        foreach (var name in startInfo.Environment.Keys.ToArray())
        {
            if (name.Equals("HTTP_PROXY", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("HTTPS_PROXY", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("ALL_PROXY", StringComparison.OrdinalIgnoreCase))
            {
                startInfo.Environment.Remove(name);
            }
        }
        return startInfo;
    }

    [ComImport, Guid("2E941141-7F97-4756-BA1D-9DECDE894A3D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IApplicationActivationManager
    {
        [PreserveSig]
        int ActivateApplication([MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
            [MarshalAs(UnmanagedType.LPWStr)] string arguments, uint options, out uint processId);

        [PreserveSig]
        int ActivateForFile([MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
            IntPtr itemArray, [MarshalAs(UnmanagedType.LPWStr)] string verb, out uint processId);

        [PreserveSig]
        int ActivateForProtocol([MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
            IntPtr itemArray, out uint processId);
    }
}
