using Microsoft.Win32;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Xml.Linq;

namespace ClaudeDesktopGuardian.Core;

public sealed record ClaudeInstallation(
    string PackageFamilyName,
    string PackageFullName,
    string PackageInstallLocation,
    IReadOnlyList<string> ExecutablePaths,
    string ActiveDataPath,
    string? MsixDataPath);

public static class ClaudeInstallDiscovery
{
    private static readonly object DiscoveryCacheLock = new();
    private static readonly TimeSpan DiscoveryCacheTtl = TimeSpan.FromSeconds(60);
    private static ClaudeInstallation? _cachedInstallation;
    private static DateTimeOffset _cachedAtUtc = DateTimeOffset.MinValue;

    internal static void ClearDiscoveryCache()
    {
        lock (DiscoveryCacheLock)
        {
            _cachedInstallation = null;
            _cachedAtUtc = DateTimeOffset.MinValue;
        }
    }

    public static ClaudeInstallation Discover(bool forceRefresh = false)
    {
        if (!forceRefresh)
        {
            lock (DiscoveryCacheLock)
            {
                if (_cachedInstallation is not null &&
                    DateTimeOffset.UtcNow - _cachedAtUtc < DiscoveryCacheTtl)
                {
                    return _cachedInstallation;
                }
            }
        }

        var roots = new List<string>();
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        foreach (var candidateRoot in new[]
                 {
                     Path.Combine(localAppData, "AnthropicClaude"),
                     Path.Combine(localAppData, "Programs", "Claude")
                 })
        {
            if (File.Exists(Path.Combine(candidateRoot, "Claude.exe")))
            {
                roots.Add(candidateRoot);
            }
        }

        var (packageFamilyName, packageFullName, packageInstallLocation) = TryFindMsixPackage();
        if (!string.IsNullOrWhiteSpace(packageInstallLocation) && Directory.Exists(packageInstallLocation))
        {
            roots.Add(packageInstallLocation);
        }

        var executables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in roots)
        {
            try
            {
                foreach (var exe in Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories))
                {
                    executables.Add(Path.GetFullPath(exe));
                }
            }
            catch
            {
            }
        }

        var msixDataPath = FindMsixDataPath(localAppData, packageFamilyName);
        var legacyDataPath = Path.Combine(appData, "Claude");
        var activeDataPath = Directory.Exists(legacyDataPath)
            ? legacyDataPath
            : !string.IsNullOrWhiteSpace(msixDataPath)
                ? msixDataPath
                : legacyDataPath;

        var discovered = new ClaudeInstallation(
            packageFamilyName,
            packageFullName,
            packageInstallLocation,
            executables.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray(),
            activeDataPath,
            msixDataPath);

        lock (DiscoveryCacheLock)
        {
            _cachedInstallation = discovered;
            _cachedAtUtc = DateTimeOffset.UtcNow;
        }

        return discovered;
    }

    public static string? FindMsixDataPath(string? localAppData = null, string? packageFamilyName = null)
    {
        localAppData ??= Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var msixRoot = Path.Combine(localAppData, "Claude-Data");
        if (!string.IsNullOrWhiteSpace(packageFamilyName))
        {
            return Path.Combine(msixRoot, packageFamilyName);
        }

        if (!Directory.Exists(msixRoot))
        {
            return null;
        }

        try
        {
            var candidates = Directory.GetDirectories(msixRoot, "claude_*", SearchOption.TopDirectoryOnly);
            return candidates.Length == 1 ? candidates[0] : null;
        }
        catch
        {
            return null;
        }
    }

    public static string? FindClaudeLaunchTarget()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        foreach (var exe in new[]
                 {
                     Path.Combine(localAppData, "AnthropicClaude", "Claude.exe"),
                     Path.Combine(localAppData, "Programs", "Claude", "Claude.exe")
                 })
        {
            if (File.Exists(exe))
            {
                return exe;
            }
        }

        var install = Discover();
        if (!string.IsNullOrWhiteSpace(install.PackageFamilyName) &&
            !string.IsNullOrWhiteSpace(install.PackageInstallLocation))
        {
            var appId = TryReadAppxApplicationId(install.PackageInstallLocation);
            if (!string.IsNullOrWhiteSpace(appId))
            {
                return $"shell:AppsFolder\\{install.PackageFamilyName}!{appId}";
            }
        }

        return null;
    }

    public static bool IsAllowedClaudeProgramPath(string path)
    {
        if (!Path.IsPathFullyQualified(path) ||
            !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(path))
        {
            return false;
        }

        var normalized = path.Replace('/', '\\');
        return normalized.Contains("\\AnthropicClaude\\", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("\\Programs\\Claude\\", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("\\Claude\\", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("\\WindowsApps\\Claude_", StringComparison.OrdinalIgnoreCase);
    }

    private static string? TryReadAppxApplicationId(string installLocation)
    {
        try
        {
            var manifestPath = Path.Combine(installLocation, "AppxManifest.xml");
            if (!File.Exists(manifestPath))
            {
                return null;
            }

            var doc = XDocument.Load(manifestPath);
            var appElement = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Application");
            return appElement?.Attribute("Id")?.Value?.Trim();
        }
        catch
        {
            return null;
        }
    }

    public static string? TryExtractPackageFamilyName(string? packageFullName)
    {
        if (string.IsNullOrWhiteSpace(packageFullName))
        {
            return null;
        }

        var parts = packageFullName.Trim().Split('_');
        if (parts.Length < 5 || string.IsNullOrWhiteSpace(parts[0]))
        {
            return null;
        }

        var publisherId = parts[^1];
        if (publisherId.Length < 8 || !publisherId.All(char.IsLetterOrDigit))
        {
            return null;
        }

        return $"{parts[0]}_{publisherId}";
    }

    private static (string FamilyName, string FullName, string InstallLocation) TryFindMsixPackage()
    {
        if (!OperatingSystem.IsWindows())
        {
            return (string.Empty, string.Empty, string.Empty);
        }

        var fromRegistry = TryFindMsixPackageFromRegistry();
        if (!string.IsNullOrWhiteSpace(fromRegistry.FamilyName))
        {
            return fromRegistry;
        }

        // Only fall back to PowerShell if Registry did not contain a valid Claude MSIX entry
        try
        {
            const string script =
                "$pkg = Get-AppxPackage -Name 'Claude' -ErrorAction SilentlyContinue | Select-Object -First 1; " +
                "if (-not $pkg) { $pkg = Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Claude*' -or $_.PackageFamilyName -like '*Claude*' } | Select-Object -First 1 }; " +
                "if ($pkg) { Write-Output ($pkg.PackageFamilyName + '|' + $pkg.PackageFullName + '|' + $pkg.InstallLocation) }";
            var startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            startInfo.ArgumentList.Add("-NoProfile");
            startInfo.ArgumentList.Add("-NonInteractive");
            startInfo.ArgumentList.Add("-EncodedCommand");
            startInfo.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return (string.Empty, string.Empty, string.Empty);
            }

            var output = process.StandardOutput.ReadToEnd().Trim();
            if (!process.WaitForExit(4000))
            {
                try { process.Kill(true); } catch { }
                return (string.Empty, string.Empty, string.Empty);
            }

            var firstLine = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (string.IsNullOrWhiteSpace(firstLine))
            {
                return (string.Empty, string.Empty, string.Empty);
            }

            var parts = firstLine.Split('|');
            if (parts.Length >= 3)
            {
                return (parts[0].Trim(), parts[1].Trim(), parts[2].Trim());
            }
        }
        catch
        {
        }

        return (string.Empty, string.Empty, string.Empty);
    }

    private static (string FamilyName, string FullName, string InstallLocation) TryFindMsixPackageFromRegistry()
    {
        try
        {
            const string packagesSubKey = @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";
            using var root = Registry.CurrentUser.OpenSubKey(packagesSubKey, writable: false);
            if (root is null)
            {
                return (string.Empty, string.Empty, string.Empty);
            }

            var names = root.GetSubKeyNames();
            var candidates = names
                .Where(n => n.StartsWith("Claude_", StringComparison.OrdinalIgnoreCase))
                .Concat(names.Where(n =>
                    !n.StartsWith("Claude_", StringComparison.OrdinalIgnoreCase) &&
                    n.Contains("Claude", StringComparison.OrdinalIgnoreCase)))
                .ToArray();

            foreach (var fullName in candidates)
            {
                using var pkgKey = root.OpenSubKey(fullName, writable: false);
                var installLocation = pkgKey?.GetValue("PackageRootFolder") as string;
                if (string.IsNullOrWhiteSpace(installLocation) || !Directory.Exists(installLocation))
                {
                    continue;
                }

                var familyName = TryExtractPackageFamilyName(fullName);
                if (!string.IsNullOrWhiteSpace(familyName))
                {
                    return (familyName, fullName, installLocation.Trim());
                }
            }
        }
        catch
        {
        }

        return (string.Empty, string.Empty, string.Empty);
    }
}

/// <summary>
/// Windows Filtering Platform (WFP) kernel-level TUN-only outbound lock for Claude Desktop.
/// Restricts IPv4/IPv6 ALE_AUTH_CONNECT outbound traffic of Claude executables and MSIX package SID
/// strictly to the verified VPN/TUN interface LUID.
/// </summary>
public sealed class WfpNetworkPolicy : IDisposable
{
    private static readonly Guid GuardianSublayerKey = new("7c4a9e31-4f82-4d1b-9a25-83e1c6b04d2f");
    private static readonly Guid PackageIdField = new("71bc78fa-f17c-4997-a602-6abb261f351c");
    private static readonly Guid AppIdField = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
    private static readonly Guid NextHopField = new("93ae8f5b-7f6f-4719-98c8-14e97429ef04");
    private static readonly Guid FlagsField = new("632ce23b-5167-435c-86d7-e903684aa80c");
    private static readonly Guid LayerAleAuthConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    private static readonly Guid LayerAleAuthConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

    private const uint ErrorMissingFilter = 0x80320003;
    private const uint ErrorMissingSublayer = 0x80320007;
    private const uint FlagPersistent = 1;
    private const uint FlagDisabled = 0x20;
    private const uint FlagClearActionRight = 8;
    private const uint ActionBlock = 0x1001;
    private const uint ActionPermit = 0x1002;
    private const int TypeUInt8 = 1;
    private const int TypeUInt32 = 3;
    private const int TypeUInt64 = 4;
    private const int TypeByteBlob = 12;
    private const int TypeSid = 13;
    private const int MatchEqual = 0;
    private const int MatchFlagsAllSet = 6;
    private const int MatchFlagsNoneSet = 8;
    private const uint ConditionFlagLoopback = 1;

    private readonly Guid _sublayerKey;
    private readonly uint _persistence;
    private IntPtr _engine;

    [StructLayout(LayoutKind.Sequential)]
    private struct DisplayData
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string Name;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByteBlob
    {
        public uint Size;
        public IntPtr Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ConditionValue
    {
        public int Type;
        public IntPtr Data;

        public ConditionValue(int type, IntPtr data)
        {
            Type = type;
            Data = data;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FilterCondition
    {
        public Guid Field;
        public int Match;
        public ConditionValue Value;

        public FilterCondition(Guid field, int match, ConditionValue value)
        {
            Field = field;
            Match = match;
            Value = value;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SublayerStruct
    {
        public Guid Key;
        public DisplayData Display;
        public uint Flags;
        public IntPtr Provider;
        public ByteBlob ProviderData;
        public ushort Weight;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FilterAction
    {
        public uint Type;
        public Guid Key;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SessionStruct
    {
        public Guid Key;
        public DisplayData Display;
        public uint Flags;
        public uint TransactionWaitMilliseconds;
        public uint ProcessId;
        public IntPtr Sid;
        public IntPtr Username;
        public int KernelMode;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct FilterContext
    {
        [FieldOffset(0)] public ulong Raw;
        [FieldOffset(0)] public Guid Key;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FilterStruct
    {
        public Guid Key;
        public DisplayData Display;
        public uint Flags;
        public IntPtr Provider;
        public ByteBlob ProviderData;
        public Guid Layer;
        public Guid Sublayer;
        public ConditionValue Weight;
        public uint ConditionCount;
        public IntPtr Conditions;
        public FilterAction Action;
        public FilterContext Context;
        public IntPtr Reserved;
        public ulong Id;
        public ConditionValue EffectiveWeight;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint FwpmEngineOpen0(
        string? server,
        uint authentication,
        IntPtr identity,
        ref SessionStruct session,
        out IntPtr handle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmEngineClose0(IntPtr handle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmTransactionBegin0(IntPtr handle, uint flags);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmTransactionAbort0(IntPtr handle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmTransactionCommit0(IntPtr handle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerAdd0(IntPtr handle, ref SublayerStruct layer, byte[] security);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerGetByKey0(IntPtr handle, ref Guid key, out IntPtr layer);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerDeleteByKey0(IntPtr handle, ref Guid key);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterAdd0(IntPtr handle, ref FilterStruct filter, byte[] security, out ulong id);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterDeleteByKey0(IntPtr handle, ref Guid key);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterGetByKey0(IntPtr handle, ref Guid key, out IntPtr filter);

    [DllImport("fwpuclnt.dll")]
    private static extern void FwpmFreeMemory0(ref IntPtr memory);

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint FwpmGetAppIdFromFileName0(string path, out IntPtr appId);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);

    [DllImport("advapi32.dll")]
    private static extern IntPtr FreeSid(IntPtr sid);

    [DllImport("iphlpapi.dll")]
    private static extern uint ConvertInterfaceGuidToLuid(ref Guid guid, out ulong luid);

    public WfpNetworkPolicy() : this(GuardianSublayerKey, false)
    {
    }

    public static WfpNetworkPolicy OpenTemporary() => new(Guid.NewGuid(), true);

    private WfpNetworkPolicy(Guid sublayerKey, bool temporary)
    {
        _sublayerKey = sublayerKey;
        _persistence = temporary ? 0u : FlagPersistent;
        var session = new SessionStruct { Flags = temporary ? 1u : 0u };
        Check(FwpmEngineOpen0(null, 10, IntPtr.Zero, ref session, out _engine), "FwpmEngineOpen0");
    }

    public static ulong InterfaceLuid(Guid adapterGuid)
    {
        Check(ConvertInterfaceGuidToLuid(ref adapterGuid, out var luid), "ConvertInterfaceGuidToLuid");
        return luid;
    }

    public void Apply(string? packageFamilyName, IReadOnlyList<string> paths, ulong interfaceLuid, bool allowLoopback = false)
    {
        if (paths is null || paths.Count == 0 || interfaceLuid == 0)
        {
            throw new ArgumentException("必须提供至少一个 Claude 可执行文件路径及有效的 TUN 接口 LUID");
        }

        var descriptor = new RawSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x80;;;AU)");
        var security = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(security, 0);
        var perIdentity = allowLoopback ? 6 : 4;

        WithIdentities(packageFamilyName, paths, identities =>
        {
            InTransaction(() =>
            {
                DeleteCore();
                var meta = Marshal.AllocHGlobal(sizeof(int) * 2);
                try
                {
                    Marshal.WriteInt32(meta, 0, identities.Length);
                    Marshal.WriteInt32(meta, sizeof(int), perIdentity);
                    var layer = new SublayerStruct
                    {
                        Key = _sublayerKey,
                        Flags = _persistence,
                        Weight = 0x8000,
                        ProviderData = new ByteBlob { Size = sizeof(int) * 2, Data = meta },
                        Display = new DisplayData
                        {
                            Name = "Claude Desktop Guardian WFP TUN-only lock",
                            Description = "Restricts Claude Desktop outbound connections to the active VPN/TUN adapter."
                        }
                    };
                    Check(FwpmSubLayerAdd0(_engine, ref layer, security), "FwpmSubLayerAdd0");
                }
                finally
                {
                    Marshal.FreeHGlobal(meta);
                }

                for (var index = 0; index < identities.Length * perIdentity; index++)
                {
                    AddFilter(index, perIdentity, identities[index / perIdentity], interfaceLuid, security);
                }
            });
        });
    }

    public void Remove()
    {
        InTransaction(DeleteCore);
    }

    public string Status(string? packageFamilyName, IReadOnlyList<string>? paths, ulong interfaceLuid, bool allowLoopback = false)
    {
        var (count, perIdentity) = ReadMetadata();
        if (count == 0)
        {
            return "off";
        }

        var expectedPerIdentity = allowLoopback ? 6 : 4;
        var expectedCount = (paths?.Count ?? 0) + (string.IsNullOrWhiteSpace(packageFamilyName) ? 0 : 1);
        if (paths is null || paths.Count == 0 || interfaceLuid == 0 ||
            count != expectedCount || perIdentity != expectedPerIdentity)
        {
            return "stale";
        }

        var valid = true;
        WithIdentities(packageFamilyName, paths, identities =>
        {
            for (var index = 0; index < count * perIdentity && valid; index++)
            {
                valid = CheckFilter(index, perIdentity, identities[index / perIdentity], interfaceLuid);
            }
        });

        return valid ? "active" : "stale";
    }

    private static (Guid Layer, FilterRole Role) DescribeSlot(int slot) => slot switch
    {
        0 => (LayerAleAuthConnectV4, FilterRole.BlockAll),
        1 => (LayerAleAuthConnectV4, FilterRole.PermitTun),
        2 => (LayerAleAuthConnectV6, FilterRole.BlockAll),
        3 => (LayerAleAuthConnectV6, FilterRole.PermitTun),
        4 => (LayerAleAuthConnectV4, FilterRole.PermitLoopback),
        5 => (LayerAleAuthConnectV6, FilterRole.PermitLoopback),
        _ => throw new ArgumentOutOfRangeException(nameof(slot))
    };

    private bool CheckFilter(int index, int perIdentity, FilterCondition identity, ulong luid)
    {
        var key = FilterKey(index);
        var result = FwpmFilterGetByKey0(_engine, ref key, out var pointer);
        if (result == ErrorMissingFilter)
        {
            return false;
        }

        Check(result, "FwpmFilterGetByKey0");
        try
        {
            var filter = Read<FilterStruct>(pointer);
            var (layer, role) = DescribeSlot(index % perIdentity);
            var isPermit = role != FilterRole.BlockAll;
            var expectedWeight = role switch
            {
                FilterRole.PermitTun => 15,
                FilterRole.PermitLoopback => 14,
                _ => 0
            };

            return filter.Sublayer == _sublayerKey &&
                   filter.Layer == layer &&
                   (filter.Flags & (FlagPersistent | FlagClearActionRight | FlagDisabled)) ==
                       (_persistence | (isPermit ? 0u : FlagClearActionRight)) &&
                   filter.Action.Type == (isPermit ? ActionPermit : ActionBlock) &&
                   filter.Weight.Type == TypeUInt8 &&
                   (filter.Weight.Data.ToInt64() & 255) == expectedWeight &&
                   ConditionsMatch(filter, identity, luid, role);
        }
        finally
        {
            FwpmFreeMemory0(ref pointer);
        }
    }

    private void AddFilter(int index, int perIdentity, FilterCondition identity, ulong luid, byte[] security)
    {
        var (layer, role) = DescribeSlot(index % perIdentity);
        var isPermit = role != FilterRole.BlockAll;
        var conditionCount = role switch
        {
            FilterRole.PermitTun => 3u,
            FilterRole.PermitLoopback => 2u,
            _ => 1u
        };
        var weight = role switch
        {
            FilterRole.PermitTun => 15,
            FilterRole.PermitLoopback => 14,
            _ => 0
        };
        var displayName = role switch
        {
            FilterRole.PermitTun => "Claude Desktop Guardian: Permit TUN only",
            FilterRole.PermitLoopback => "Claude Desktop Guardian: Permit Loopback",
            _ => "Claude Desktop Guardian: Block non-TUN routes"
        };

        var nextHop = Marshal.AllocHGlobal(sizeof(ulong));
        var conditionSize = Marshal.SizeOf<FilterCondition>();
        var conditions = Marshal.AllocHGlobal(conditionSize * (int)conditionCount);
        try
        {
            Marshal.WriteInt64(nextHop, unchecked((long)luid));
            WriteCondition(conditions, 0, identity);
            if (role == FilterRole.PermitTun)
            {
                WriteCondition(conditions, 1, new FilterCondition(NextHopField, MatchEqual, new ConditionValue(TypeUInt64, nextHop)));
                WriteCondition(conditions, 2, new FilterCondition(FlagsField, MatchFlagsNoneSet, new ConditionValue(TypeUInt32, new IntPtr(ConditionFlagLoopback))));
            }
            else if (role == FilterRole.PermitLoopback)
            {
                WriteCondition(conditions, 1, new FilterCondition(FlagsField, MatchFlagsAllSet, new ConditionValue(TypeUInt32, new IntPtr(ConditionFlagLoopback))));
            }

            var filter = new FilterStruct
            {
                Key = FilterKey(index),
                Layer = layer,
                Sublayer = _sublayerKey,
                Flags = _persistence | (isPermit ? 0u : FlagClearActionRight),
                Weight = new ConditionValue(TypeUInt8, new IntPtr(weight)),
                ConditionCount = conditionCount,
                Conditions = conditions,
                Action = new FilterAction { Type = isPermit ? ActionPermit : ActionBlock },
                Display = new DisplayData { Name = displayName }
            };
            Check(FwpmFilterAdd0(_engine, ref filter, security, out _), "FwpmFilterAdd0");
        }
        finally
        {
            Marshal.FreeHGlobal(conditions);
            Marshal.FreeHGlobal(nextHop);
        }
    }

    private static bool ConditionsMatch(FilterStruct filter, FilterCondition expected, ulong luid, FilterRole role)
    {
        var expectedCount = role switch
        {
            FilterRole.PermitTun => 3u,
            FilterRole.PermitLoopback => 2u,
            _ => 1u
        };
        if (filter.ConditionCount != expectedCount || filter.Conditions == IntPtr.Zero)
        {
            return false;
        }

        var size = Marshal.SizeOf<FilterCondition>();
        var identityMatched = false;
        var nextHopMatched = false;
        var nonLoopbackMatched = false;
        var loopbackMatched = false;

        for (var i = 0; i < filter.ConditionCount; i++)
        {
            var condition = Read<FilterCondition>(IntPtr.Add(filter.Conditions, size * i));
            if (condition.Field == expected.Field &&
                condition.Match == MatchEqual &&
                condition.Value.Type == expected.Value.Type)
            {
                identityMatched = condition.Value.Type == TypeSid
                    ? new SecurityIdentifier(expected.Value.Data).Equals(new SecurityIdentifier(condition.Value.Data))
                    : string.Equals(ReadBlobString(expected.Value.Data), ReadBlobString(condition.Value.Data), StringComparison.Ordinal);
            }

            if (condition.Field == NextHopField &&
                condition.Match == MatchEqual &&
                condition.Value.Type == TypeUInt64 &&
                condition.Value.Data != IntPtr.Zero)
            {
                nextHopMatched = luid != 0 && unchecked((ulong)Marshal.ReadInt64(condition.Value.Data)) == luid;
            }

            if (condition.Field == FlagsField &&
                condition.Match == MatchFlagsNoneSet &&
                condition.Value.Type == TypeUInt32)
            {
                nonLoopbackMatched = unchecked((uint)condition.Value.Data.ToInt64()) == ConditionFlagLoopback;
            }

            if (condition.Field == FlagsField &&
                condition.Match == MatchFlagsAllSet &&
                condition.Value.Type == TypeUInt32)
            {
                loopbackMatched = unchecked((uint)condition.Value.Data.ToInt64()) == ConditionFlagLoopback;
            }
        }

        return role switch
        {
            FilterRole.BlockAll => identityMatched,
            FilterRole.PermitTun => identityMatched && nextHopMatched && nonLoopbackMatched,
            FilterRole.PermitLoopback => identityMatched && loopbackMatched,
            _ => false
        };
    }

    private static string? ReadBlobString(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero)
        {
            return null;
        }

        var blob = Read<ByteBlob>(pointer);
        return blob.Data != IntPtr.Zero && blob.Size > 0 && blob.Size <= 65536 && blob.Size % 2 == 0
            ? Marshal.PtrToStringUni(blob.Data, (int)blob.Size / 2)?.TrimEnd('\0')
            : null;
    }

    private void DeleteCore()
    {
        var (count, perIdentity) = ReadMetadata();
        if (count == 0)
        {
            return;
        }

        for (var index = 0; index < count * perIdentity; index++)
        {
            var key = FilterKey(index);
            var result = FwpmFilterDeleteByKey0(_engine, ref key);
            if (result != ErrorMissingFilter)
            {
                Check(result, "FwpmFilterDeleteByKey0");
            }
        }

        var sublayer = _sublayerKey;
        var sublayerResult = FwpmSubLayerDeleteByKey0(_engine, ref sublayer);
        if (sublayerResult != ErrorMissingSublayer)
        {
            Check(sublayerResult, "FwpmSubLayerDeleteByKey0");
        }
    }

    private (int IdentityCount, int FiltersPerIdentity) ReadMetadata()
    {
        var key = _sublayerKey;
        var result = FwpmSubLayerGetByKey0(_engine, ref key, out var pointer);
        if (result == ErrorMissingSublayer)
        {
            return (0, 4);
        }

        Check(result, "FwpmSubLayerGetByKey0");
        try
        {
            var data = Read<SublayerStruct>(pointer).ProviderData;
            if (data.Data == IntPtr.Zero || (data.Size != sizeof(int) && data.Size != sizeof(int) * 2))
            {
                throw new InvalidOperationException("WFP 子层元数据格式异常");
            }

            var count = Marshal.ReadInt32(data.Data, 0);
            var perIdentity = data.Size == sizeof(int) * 2 ? Marshal.ReadInt32(data.Data, sizeof(int)) : 4;
            if (count <= 0 || count > 1024 || (perIdentity != 4 && perIdentity != 6))
            {
                throw new InvalidOperationException("WFP 子层元数据数值异常");
            }

            return (count, perIdentity);
        }
        finally
        {
            FwpmFreeMemory0(ref pointer);
        }
    }

    private static void WithIdentities(
        string? packageFamilyName,
        IReadOnlyList<string> paths,
        Action<FilterCondition[]> action)
    {
        var hasPackage = !string.IsNullOrWhiteSpace(packageFamilyName);
        var identities = new FilterCondition[paths.Count + (hasPackage ? 1 : 0)];
        if (identities.Length > 1024)
        {
            throw new ArgumentException("身份数量超出 WFP 保护上限");
        }

        var sid = IntPtr.Zero;
        var appIds = new IntPtr[paths.Count];
        try
        {
            if (hasPackage)
            {
                Marshal.ThrowExceptionForHR(DeriveAppContainerSidFromAppContainerName(packageFamilyName!, out sid));
                identities[paths.Count] = new FilterCondition(PackageIdField, MatchEqual, new ConditionValue(TypeSid, sid));
            }

            for (var index = 0; index < paths.Count; index++)
            {
                Check(FwpmGetAppIdFromFileName0(paths[index], out appIds[index]), "FwpmGetAppIdFromFileName0");
                identities[index] = new FilterCondition(AppIdField, MatchEqual, new ConditionValue(TypeByteBlob, appIds[index]));
            }

            action(identities);
        }
        finally
        {
            for (var i = 0; i < appIds.Length; i++)
            {
                var ptr = appIds[i];
                if (ptr != IntPtr.Zero)
                {
                    FwpmFreeMemory0(ref ptr);
                }
            }

            if (sid != IntPtr.Zero)
            {
                FreeSid(sid);
            }
        }
    }

    private Guid FilterKey(int index)
    {
        var key = _sublayerKey.ToByteArray();
        key[0] ^= 1;
        key[14] ^= (byte)(index >> 8);
        key[15] ^= (byte)index;
        return new Guid(key);
    }

    private void InTransaction(Action action)
    {
        Check(FwpmTransactionBegin0(_engine, 0), "FwpmTransactionBegin0");
        try
        {
            action();
            Check(FwpmTransactionCommit0(_engine), "FwpmTransactionCommit0");
        }
        catch
        {
            FwpmTransactionAbort0(_engine);
            throw;
        }
    }

    private static void WriteCondition(IntPtr array, int index, FilterCondition condition)
    {
        Marshal.StructureToPtr(condition, IntPtr.Add(array, index * Marshal.SizeOf<FilterCondition>()), false);
    }

    private static T Read<T>(IntPtr pointer) where T : struct => Marshal.PtrToStructure<T>(pointer);

    private static void Check(uint result, string operation)
    {
        if (result != 0)
        {
            throw new Win32Exception(unchecked((int)result), $"{operation}: 0x{result:X8}");
        }
    }

    public void Dispose()
    {
        if (_engine == IntPtr.Zero)
        {
            return;
        }

        FwpmEngineClose0(_engine);
        _engine = IntPtr.Zero;
    }

    private enum FilterRole
    {
        BlockAll,
        PermitTun,
        PermitLoopback
    }
}
