using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ClaudeDesktopGuardian.Core;

public sealed class WindowsEnvironmentProbe : IEnvironmentProbe
{
    private static readonly HttpClient Http = CreateHttpClient(AddressFamily.InterNetwork, useSystemProxy: true);
    private static readonly HttpClient Ipv6Http = CreateHttpClient(AddressFamily.InterNetworkV6, useSystemProxy: false);
    private TraceResolution _lastIpv6Trace = TraceResolution.Empty;
    private TimezoneResolution? _lastTimezone;

    public async Task<NetworkSnapshot> CaptureNetworkAsync(
        GuardianConfig config,
        IReadOnlyList<ProcessInfo> protectedProcesses,
        bool full,
        CancellationToken cancellationToken)
    {
        var adapter = FindVpnAdapter(config.VpnAdapterPattern);
        var localAddress = adapter?.GetIPProperties().UnicastAddresses
            .FirstOrDefault(address => address.Address.AddressFamily == AddressFamily.InterNetwork)
            ?.Address.ToString() ?? string.Empty;
        var gateway = adapter?.GetIPProperties().GatewayAddresses
            .FirstOrDefault(address => address.Address.AddressFamily == AddressFamily.InterNetwork)
            ?.Address.ToString() ?? string.Empty;
        var dnsServers = adapter?.GetIPProperties().DnsAddresses
            .Select(address => address.ToString())
            .ToArray() ?? Array.Empty<string>();
        TimeZoneInfo.ClearCachedData();
        var currentWindowsTimezone = TimeZoneInfo.Local.Id;
        var hasIpv6 = HasIpv6Route(adapter);

        var traceTask = adapter is null
            ? Task.FromResult(TraceResolution.Empty)
            : TryGetTraceAsync(Http, AddressFamily.InterNetwork, cancellationToken);
        var ipv6TraceTask = adapter is null || !full
            ? Task.FromResult(_lastIpv6Trace)
            : hasIpv6
                ? TryGetTraceAsync(Ipv6Http, AddressFamily.InterNetworkV6, cancellationToken)
                : Task.FromResult(TraceResolution.Empty);
        var stunTask = ProbeStunAsync(config.EffectiveStunServers, hasIpv6, cancellationToken);
        var connections = CaptureConnections(protectedProcesses);
        var claudeTask = full
            ? ProbeClaudeHttpsAsync(config.EffectiveClaudeDomains, cancellationToken)
            : Task.FromResult<IReadOnlyDictionary<string, string>>(
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));
        var timezoneTask = adapter is null || !full
            ? Task.FromResult(_lastTimezone)
            : new ExitTimezoneResolver(Http).ResolveAsync(cancellationToken);

        var trace = await traceTask;
        var ipv6Trace = await ipv6TraceTask;
        if (full && adapter is not null)
        {
            _lastIpv6Trace = ipv6Trace;
        }

        var stunResults = await stunTask;
        var claudeHttps = await claudeTask;
        var timezone = await timezoneTask;
        if (full && adapter is not null && timezone is null)
        {
            timezone = await new ExitTimezoneResolver(Ipv6Http).ResolveAsync(cancellationToken);
        }
        if (full && adapter is not null && timezone is not null)
        {
            _lastTimezone = timezone;
        }
        var exitIp = trace.Ip;
        var exitCountry = trace.Country;
        var exitIpv6 = ipv6Trace.Ip;
        var exitIpv6Country = ipv6Trace.Country;
        return new NetworkSnapshot(
            adapter?.Name ?? string.Empty,
            adapter?.Description ?? string.Empty,
            localAddress,
            gateway,
            exitIp,
            exitCountry,
            exitIpv6,
            exitIpv6Country,
            dnsServers,
            stunResults,
            connections,
            hasIpv6,
            claudeHttps,
            timezone?.IanaId ?? string.Empty,
            timezone?.WindowsId ?? string.Empty,
            currentWindowsTimezone,
            ipv6Trace.Detail,
            trace.Detail);
    }

    private static NetworkInterface? FindVpnAdapter(string? pattern)
    {
        var interfaces = NetworkInterface.GetAllNetworkInterfaces()
            .Where(item => item.OperationalStatus == OperationalStatus.Up)
            .Where(item => item.NetworkInterfaceType != NetworkInterfaceType.Loopback);

        if (!string.IsNullOrWhiteSpace(pattern))
        {
            interfaces = interfaces.Where(item =>
                item.Name.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains(pattern, StringComparison.OrdinalIgnoreCase));
        }
        else
        {
            interfaces = interfaces.Where(item =>
                item.Description.Contains("TUN", StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains("TAP", StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains("Wintun", StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains("VPN", StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains("Tailscale", StringComparison.OrdinalIgnoreCase) ||
                item.GetIPProperties().UnicastAddresses.Any(address =>
                    address.Address.ToString().StartsWith("198.18.", StringComparison.Ordinal)));
        }

        return interfaces.FirstOrDefault();
    }

    private static bool IsGlobalIpv6(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetworkV6 ||
            address.IsIPv6LinkLocal ||
            address.IsIPv6SiteLocal ||
            address.IsIPv6Multicast ||
            IPAddress.IsLoopback(address))
        {
            return false;
        }

        var firstByte = address.GetAddressBytes()[0];
        return firstByte is not 0xFC and not 0xFD;
    }

    private static bool HasIpv6Route(NetworkInterface? adapter)
    {
        if (adapter is null ||
            adapter.OperationalStatus != OperationalStatus.Up)
        {
            return false;
        }

        var properties = adapter.GetIPProperties();
        var hasIpv6Address = properties.UnicastAddresses
            .Any(address =>
                address.Address.AddressFamily == AddressFamily.InterNetworkV6 &&
                !address.Address.IsIPv6LinkLocal &&
                !address.Address.IsIPv6Multicast &&
                !IPAddress.IsLoopback(address.Address));
        var hasIpv6Gateway = properties.GatewayAddresses
            .Any(address =>
                address.Address.AddressFamily == AddressFamily.InterNetworkV6 &&
                !address.Address.IsIPv6Multicast);
        return hasIpv6Address && hasIpv6Gateway;
    }

    private static async Task<TraceResolution> TryGetTraceAsync(
        HttpClient client,
        AddressFamily addressFamily,
        CancellationToken cancellationToken)
    {
        try
        {
            using var response = await client.GetAsync(
                "https://www.cloudflare.com/cdn-cgi/trace",
                cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            var values = body.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Split('=', 2))
                .Where(parts => parts.Length == 2)
                .ToDictionary(parts => parts[0].Trim(), parts => parts[1].Trim());
            var ip = values.GetValueOrDefault("ip", string.Empty);
            var country = values.GetValueOrDefault("loc", string.Empty);
            if (!IPAddress.TryParse(ip, out var parsedIp) ||
                (addressFamily == AddressFamily.InterNetworkV6 &&
                 parsedIp.AddressFamily != AddressFamily.InterNetworkV6))
            {
                var familyName = addressFamily == AddressFamily.InterNetworkV6
                    ? "IPv6"
                    : "IPv4";
                return new TraceResolution(
                    string.Empty,
                    country,
                    $"{familyName} 连接已建立，但出口服务返回的地址不是 {familyName}");
            }

            return new TraceResolution(
                ip,
                country,
                addressFamily == AddressFamily.InterNetworkV6
                    ? "已通过 VPN IPv6 路由取得公网 IPv6 出口"
                    : string.Empty);
        }
        catch (Exception exception)
        {
            var familyName = addressFamily == AddressFamily.InterNetworkV6
                ? "IPv6"
                : "IPv4";
            return new TraceResolution(
                string.Empty,
                string.Empty,
                $"{familyName} 出口探测失败：{exception.GetType().Name} {exception.Message}");
        }
    }

    private static async Task<IReadOnlyDictionary<string, string>> ProbeClaudeHttpsAsync(
        IReadOnlyList<string> domains,
        CancellationToken cancellationToken)
    {
        var results = await Task.WhenAll(domains.Select(async domain =>
        {
            var status = string.Empty;
            try
            {
                using var response = await Http.GetAsync(
                    $"https://{domain}/",
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken);
                status = ((int)response.StatusCode).ToString();
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                status = "timeout";
            }
            catch (Exception exception)
            {
                status = exception.GetType().Name;
            }

            return new KeyValuePair<string, string>(domain, status);
        }));

        return results.ToDictionary(
            pair => pair.Key,
            pair => pair.Value,
            StringComparer.OrdinalIgnoreCase);
    }

    private static async Task<IReadOnlyList<StunResult>> ProbeStunAsync(
        IReadOnlyList<(string Host, int Port)> servers,
        bool probeIpv6,
        CancellationToken cancellationToken)
    {
        return await Task.WhenAll(
            servers.SelectMany(server =>
            {
                var families = probeIpv6
                    ? new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 }
                    : new[] { AddressFamily.InterNetwork };
                return families.Select(family =>
                    ProbeOneStunAsync(server.Host, server.Port, family, cancellationToken));
            }));
    }

    private static async Task<StunResult> ProbeOneStunAsync(
        string host,
        int port,
        AddressFamily addressFamily,
        CancellationToken cancellationToken)
    {
        try
        {
            var addresses = (await Dns.GetHostAddressesAsync(host, cancellationToken))
                .Where(item => item.AddressFamily == addressFamily)
                .Distinct()
                .ToArray();
            if (addresses.Length == 0)
            {
                return new StunResult(
                    host,
                    port,
                    "unknown",
                    string.Empty,
                    $"未取得 {FormatAddressFamily(addressFamily)} 地址");
            }

            var details = new List<string>();
            foreach (var address in addresses)
            {
                var result = await ProbeStunAddressAsync(
                    host,
                    port,
                    address,
                    addressFamily,
                    cancellationToken);
                if (result.Status == "ok")
                {
                    return result;
                }

                details.Add(result.Detail);
            }

            return new StunResult(
                host,
                port,
                "unknown",
                string.Empty,
                string.Join("；", details));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new StunResult(
                host,
                port,
                "unknown",
                string.Empty,
                $"{FormatAddressFamily(addressFamily)} STUN 超时");
        }
        catch (Exception exception)
        {
            return new StunResult(
                host,
                port,
                "unknown",
                string.Empty,
                $"{FormatAddressFamily(addressFamily)} {exception.GetType().Name}");
        }
    }

    private static async Task<StunResult> ProbeStunAddressAsync(
        string host,
        int port,
        IPAddress address,
        AddressFamily addressFamily,
        CancellationToken cancellationToken)
    {
        try
        {
            using var udp = new UdpClient(addressFamily);
            var transaction = Random.Shared.GetItems(
                new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 },
                12);
            var request = new byte[20];
            request[0] = 0x00;
            request[1] = 0x01;
            request[4] = 0x21;
            request[5] = 0x12;
            request[6] = 0xA4;
            request[7] = 0x42;
            Buffer.BlockCopy(transaction, 0, request, 8, 12);

            await udp.SendAsync(request, request.Length, new IPEndPoint(address, port));
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            var received = await udp.ReceiveAsync(timeout.Token);
            var mapped = ParseMappedAddress(received.Buffer, transaction);
            return mapped is null
                ? new StunResult(
                    host,
                    port,
                    "unknown",
                    string.Empty,
                    $"{FormatAddressFamily(addressFamily)} 响应未包含有效映射地址")
                : new StunResult(
                    host,
                    port,
                    "ok",
                    mapped,
                    $"{FormatAddressFamily(addressFamily)} 收到 STUN 映射地址");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new StunResult(
                host,
                port,
                "unknown",
                string.Empty,
                $"{FormatAddressFamily(addressFamily)} STUN 超时");
        }
        catch (Exception exception)
        {
            return new StunResult(
                host,
                port,
                "unknown",
                string.Empty,
                $"{FormatAddressFamily(addressFamily)} {exception.GetType().Name}");
        }
    }

    private static string? ParseMappedAddress(byte[] response, byte[] transaction)
    {
        if (response.Length < 20)
        {
            return null;
        }

        for (var position = 20; position + 4 <= response.Length;)
        {
            var type = (response[position] << 8) | response[position + 1];
            var length = (response[position + 2] << 8) | response[position + 3];
            if (position + 4 + length > response.Length)
            {
                return null;
            }

            if ((type == 0x0001 || type == 0x0020) &&
                length >= 8 &&
                response[position + 5] == 0x01)
            {
                var bytes = new byte[4];
                Buffer.BlockCopy(response, position + 8, bytes, 0, 4);
                if (type == 0x0020)
                {
                    var cookie = new byte[] { 0x21, 0x12, 0xA4, 0x42 };
                    for (var index = 0; index < 4; index++)
                    {
                        bytes[index] ^= cookie[index];
                    }
                }

                return new IPAddress(bytes).ToString();
            }
            else if ((type == 0x0001 || type == 0x0020) &&
                     length >= 20 &&
                     response[position + 5] == 0x02)
            {
                var bytes = new byte[16];
                Buffer.BlockCopy(response, position + 8, bytes, 0, 16);
                if (type == 0x0020)
                {
                    var cookie = new byte[] { 0x21, 0x12, 0xA4, 0x42 };
                    for (var index = 0; index < 4; index++)
                    {
                        bytes[index] ^= cookie[index];
                    }

                    for (var index = 0; index < 12; index++)
                    {
                        bytes[index + 4] ^= transaction[index];
                    }
                }

                return new IPAddress(bytes).ToString();
            }

            position += 4 + length + ((4 - (length % 4)) % 4);
        }

        return null;
    }

    private static string FormatAddressFamily(AddressFamily addressFamily) =>
        addressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4";

    private static IReadOnlyList<string> CaptureConnections(IReadOnlyList<ProcessInfo> processes)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Array.Empty<string>();
        }

        try
        {
            var processIds = processes.Select(process => (uint)process.ProcessId).ToHashSet();
            var rows = ReadTcpRows();
            return rows
                .Where(row => row.State == TcpState.Established && processIds.Contains(row.ProcessId))
                .Select(row => $"{row.ProcessId} {row.RemoteAddress}:{row.RemotePort}")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static IReadOnlyList<TcpRow> ReadTcpRows()
    {
        var size = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2, 5, 0);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, true, 2, 5, 0) != 0)
            {
                return Array.Empty<TcpRow>();
            }

            var count = Marshal.ReadInt32(buffer);
            var rows = new List<TcpRow>(count);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            var current = buffer + sizeof(int);
            for (var index = 0; index < count; index++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(current);
                var remoteAddress = new IPAddress(row.RemoteAddress).ToString();
                var remotePort = (ushort)IPAddress.NetworkToHostOrder((short)row.RemotePort);
                rows.Add(new TcpRow(
                    (TcpState)row.State,
                    row.ProcessId,
                    remoteAddress,
                    remotePort));
                current += rowSize;
            }

            return rows;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable,
        ref int bufferLength,
        bool sort,
        int addressFamily,
        int tableClass,
        uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint ProcessId;
    }

    private sealed record TcpRow(
        TcpState State,
        uint ProcessId,
        string RemoteAddress,
        ushort RemotePort);

    private static HttpClient CreateHttpClient(
        AddressFamily addressFamily,
        bool useSystemProxy)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = useSystemProxy
        };

        if (!useSystemProxy && addressFamily == AddressFamily.InterNetworkV6)
        {
            handler.ConnectCallback = async (context, cancellationToken) =>
            {
                var addresses = (await Dns.GetHostAddressesAsync(
                    context.DnsEndPoint.Host,
                    cancellationToken))
                    .Where(item => item.AddressFamily == addressFamily)
                    .Distinct()
                    .ToArray();
                if (addresses.Length == 0)
                {
                    throw new HttpRequestException($"没有找到 {addressFamily} 出口地址");
                }

                Exception? lastException = null;
                foreach (var address in addresses)
                {
                    var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
                        using var attemptTimeout =
                            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                        attemptTimeout.CancelAfter(TimeSpan.FromSeconds(3));
                        await socket.ConnectAsync(
                            new IPEndPoint(address, context.DnsEndPoint.Port),
                            attemptTimeout.Token);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (Exception exception)
                    {
                        lastException = exception;
                        socket.Dispose();
                    }
                }

                throw new HttpRequestException(
                    $"无法连接 {context.DnsEndPoint.Host} 的 {addressFamily} 地址",
                    lastException);
            };
        }

        return new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(8)
        };
    }

    private sealed record TraceResolution(string Ip, string Country, string Detail)
    {
        public static TraceResolution Empty { get; } =
            new(string.Empty, string.Empty, string.Empty);
    }
}

