using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ClaudeDesktopGuardian.Core;

public sealed record NativeRoute(int InterfaceIndex, IPAddress Prefix, int PrefixLength, uint Metric,
    string NextHop = "", long InterfaceLuid = 0);
public sealed record RouteTableEvidence(IReadOnlyList<NativeRoute> Routes, CollectionObservation Observation);
public sealed record ConnectionTableEvidence(IReadOnlyList<TransportEndpoint> Tcp,
    IReadOnlyList<TransportEndpoint> Udp, CollectionObservation Observation);

public interface INativeNetworkApi
{
    uint ReadTransportTable(bool udp, int family, IntPtr buffer, ref int size);
    IReadOnlyList<NativeRoute> ReadRoutes();
    int BestRoute(IPAddress destination);
}

public sealed class WindowsNativeNetworkApi : INativeNetworkApi
{
    public uint ReadTransportTable(bool udp, int family, IntPtr buffer, ref int size) => udp
        ? GetExtendedUdpTable(buffer, ref size, false, family, 1, 0)
        : GetExtendedTcpTable(buffer, ref size, false, family, 5, 0);

    public IReadOnlyList<NativeRoute> ReadRoutes()
    {
        var error = GetIpForwardTable2(0, out var table);
        if (error != 0) throw new Win32Exception((int)error);
        if (table == IntPtr.Zero) throw new InvalidOperationException("路由表指针为空");
        try
        {
            var count = Marshal.ReadInt32(table);
            if (count < 0 || count > 1_000_000) throw new InvalidOperationException("路由表长度无效");
            var routes = new List<NativeRoute>(count);
            for (var index = 0; index < count; index++)
            {
                var row = IntPtr.Add(table, 8 + index * 104);
                var family = Marshal.ReadInt16(row, 12);
                if (family != 2 && family != 23) continue;
                var bytes = new byte[family == 2 ? 4 : 16];
                Marshal.Copy(IntPtr.Add(row, family == 2 ? 16 : 20), bytes, 0, bytes.Length);
                var nextHop = new byte[bytes.Length];
                Marshal.Copy(IntPtr.Add(row, family == 2 ? 48 : 52), nextHop, 0, nextHop.Length);
                routes.Add(new NativeRoute(Marshal.ReadInt32(row, 8), new IPAddress(bytes),
                    Marshal.ReadByte(row, 40), unchecked((uint)Marshal.ReadInt32(row, 84)), new IPAddress(nextHop).ToString(),
                    Marshal.ReadInt64(row)));
            }
            return routes;
        }
        finally { FreeMibTable(table); }
    }

    public int BestRoute(IPAddress destination)
    {
        var address = new byte[28];
        var ipv6 = destination.AddressFamily == AddressFamily.InterNetworkV6;
        BitConverter.GetBytes((short)(ipv6 ? 23 : 2)).CopyTo(address, 0);
        destination.GetAddressBytes().CopyTo(address, ipv6 ? 8 : 4);
        if (ipv6) BitConverter.GetBytes((uint)destination.ScopeId).CopyTo(address, 24);
        var row = Marshal.AllocHGlobal(104);
        try
        {
            var error = GetBestRoute2(IntPtr.Zero, 0, IntPtr.Zero, address, 0, row, new byte[28]);
            if (error != 0) throw new Win32Exception((int)error);
            return Marshal.ReadInt32(row, 8);
        }
        finally { Marshal.FreeHGlobal(row); }
    }

    [DllImport("iphlpapi.dll")]
    private static extern uint GetBestRoute2(IntPtr luid, uint index, IntPtr source,
        byte[] destination, uint options, IntPtr route, [Out] byte[] bestSource);
    [DllImport("iphlpapi.dll")]
    private static extern uint GetIpForwardTable2(ushort family, out IntPtr table);
    [DllImport("iphlpapi.dll")]
    private static extern void FreeMibTable(IntPtr table);
    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(IntPtr buffer, ref int size, bool sort,
        int family, int tableClass, uint reserved);
    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedUdpTable(IntPtr buffer, ref int size, bool sort,
        int family, int tableClass, uint reserved);
}

public sealed class NativeNetworkEvidence
{
    private readonly INativeNetworkApi _api;
    public NativeNetworkEvidence(INativeNetworkApi? api = null) => _api = api ?? new WindowsNativeNetworkApi();

    public RouteTableEvidence CaptureRoutes(DateTimeOffset now)
    {
        try { return new(_api.ReadRoutes(), new(true, now)); }
        catch (Exception error) { return new(Array.Empty<NativeRoute>(), new(false, now, error.GetType().Name)); }
    }

    public DestinationRoute InspectRoute(IPAddress destination, int expectedIndex)
    {
        try { return new(destination.ToString(), _api.BestRoute(destination), expectedIndex, true); }
        catch (Exception error) { return new(destination.ToString(), 0, expectedIndex, false, error.GetType().Name); }
    }

    public ConnectionTableEvidence CaptureConnections(IReadOnlyList<ProcessInfo> processes, DateTimeOffset now)
    {
        var tcp = new List<TransportEndpoint>();
        var udp = new List<TransportEndpoint>();
        try
        {
            var owners = processes.Select(process => process.ProcessId).ToHashSet();
            foreach (var family in new[] { 2, 23 })
            {
                ReadRows(false, family, owners, tcp);
                ReadRows(true, family, owners, udp);
            }
            return new(tcp, udp, new(true, now));
        }
        catch (Exception error) { return new(tcp, udp, new(false, now, error.GetType().Name)); }
    }

    private void ReadRows(bool udp, int family, HashSet<int> owners, List<TransportEndpoint> rows)
    {
        var size = 0;
        var error = _api.ReadTransportTable(udp, family, IntPtr.Zero, ref size);
        if (error != 0 && error != 122) throw new Win32Exception((int)error);
        for (var attempt = 0; attempt < 4; attempt++)
        {
            if (size < 4 || size > 64 * 1024 * 1024) throw new InvalidOperationException("端点表大小无效");
            var capacity = size;
            var buffer = Marshal.AllocHGlobal(capacity);
            try
            {
                error = _api.ReadTransportTable(udp, family, buffer, ref size);
                if (error == 122) continue;
                if (error != 0) throw new Win32Exception((int)error);
                var rowSize = udp ? family == 2 ? 12 : 28 : family == 2 ? 24 : 56;
                var count = Marshal.ReadInt32(buffer);
                if (count < 0 || count > (capacity - 4) / rowSize)
                    throw new InvalidOperationException("端点表长度无效");
                for (var index = 0; index < count; index++)
                {
                    var row = IntPtr.Add(buffer, 4 + index * rowSize);
                    var pid = Marshal.ReadInt32(row, rowSize - 4);
                    if (!owners.Contains(pid)) continue;
                    if (!udp && Marshal.ReadInt32(row, family == 2 ? 0 : 48) != (int)TcpState.Established) continue;
                    var localOffset = family == 2 && !udp ? 4 : 0;
                    var localPortOffset = family == 2 ? udp ? 4 : 8 : 20;
                    var local = ReadAddress(row, localOffset, family, family == 23 ? 16 : -1);
                    var remote = udp ? "" : ReadAddress(row, family == 2 ? 12 : 24, family, family == 23 ? 40 : -1);
                    rows.Add(new(pid, udp ? "UDP" : "TCP", local, ReadPort(row, localPortOffset), remote,
                        udp ? 0 : ReadPort(row, family == 2 ? 16 : 44)));
                }
                return;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        throw new InvalidOperationException("端点表持续变化，未能完成采集");
    }

    private static string ReadAddress(IntPtr row, int offset, int family, int scopeOffset)
    {
        var bytes = new byte[family == 2 ? 4 : 16];
        Marshal.Copy(IntPtr.Add(row, offset), bytes, 0, bytes.Length);
        return family == 2 ? new IPAddress(bytes).ToString()
            : new IPAddress(bytes, unchecked((uint)Marshal.ReadInt32(row, scopeOffset))).ToString();
    }

    private static int ReadPort(IntPtr row, int offset) =>
        (ushort)IPAddress.NetworkToHostOrder(Marshal.ReadInt16(row, offset));

    public static string ContextKey(IEnumerable<string> adapterState, RouteTableEvidence routes, string proxy)
    {
        var routeState = routes.Observation.Succeeded
            ? string.Join(";", routes.Routes.Select(route => $"{route.InterfaceIndex}:{route.InterfaceLuid}:{route.Prefix}/{route.PrefixLength}:{route.Metric}:{route.NextHop}")
                .OrderBy(value => value, StringComparer.Ordinal)) : "unreadable";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            string.Join(";", adapterState.OrderBy(value => value, StringComparer.Ordinal)) + "|" + routeState + "|" + proxy)));
    }
}
