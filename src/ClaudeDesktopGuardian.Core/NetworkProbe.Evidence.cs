using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;

namespace ClaudeDesktopGuardian.Core;

public sealed partial class WindowsEnvironmentProbe
{
    private readonly NativeNetworkEvidence _nativeEvidence;
    private readonly IGuardianClock _clock;
    private readonly Dictionary<string, CollectionObservation> _observations = new(StringComparer.OrdinalIgnoreCase);
    private string _networkContext = "";
    private bool _contextChanged;
    private DateTimeOffset _cycleStartedAt;
    private IReadOnlyList<string> _connections = Array.Empty<string>();
    private IReadOnlyList<TransportEndpoint> _udpEndpoints = Array.Empty<TransportEndpoint>();
    private IReadOnlyList<string> _publicIpv6Routes = Array.Empty<string>();
    private IReadOnlyList<string> _lastProbeDestinations = Array.Empty<string>();
    private ProbeRouteContext? _routeContext;
    private static readonly AsyncLocal<ProbeRouteContext?> ActiveProbeRoute = new();

    internal sealed record ProbeRouteContext(NativeNetworkEvidence Native, int Ipv4Index, int Ipv6Index,
        bool LocalSystemProxy, List<DestinationRoute> Results)
    {
        public void Validate(IPAddress address, bool systemProxy)
        {
            if (systemProxy && LocalSystemProxy && IPAddress.IsLoopback(address)) return;
            var result = Native.InspectRoute(address,
                address.AddressFamily == AddressFamily.InterNetwork ? Ipv4Index : Ipv6Index);
            lock (Results) Results.Add(result);
            if (!result.Matches) throw new HttpRequestException("具体目标最佳路由不经已识别 TUN，已在发送前拒绝连接");
        }
    }

    private void PrepareEvidence(NetworkInterface? adapter, IReadOnlyList<ProcessInfo> processes, GuardianConfig config,
        bool refreshDestinations = false)
    {
        _cycleStartedAt = _clock.UtcNow;
        var routeTable = _nativeEvidence.CaptureRoutes(_cycleStartedAt);
        var proxy = DetectSystemProxy();
        var state = NetworkInterface.GetAllNetworkInterfaces().Select(nic =>
            nic.Id + ":" + nic.OperationalStatus + ":" + GetIpv4InterfaceIndex(nic) + ":" + GetIpv6InterfaceIndex(nic) + ":" +
            string.Join(",", nic.GetIPProperties().UnicastAddresses.Select(address => address.Address.ToString())) + ":" +
            string.Join(",", nic.GetIPProperties().DnsAddresses.Select(address => address.ToString())));
        var context = NativeNetworkEvidence.ContextKey(state.Append(adapter?.Id ?? ""), routeTable,
            proxy + JsonSerializer.Serialize(config));
        _contextChanged = !string.Equals(_networkContext, context, StringComparison.Ordinal);
        if (_contextChanged) InvalidateCachedEvidence();
        if (refreshDestinations) _lastProbeDestinations = Array.Empty<string>();
        _networkContext = context;
        foreach (var key in _observations.Keys.ToArray())
            _observations[key] = _observations[key] with { IsCached = true };
        foreach (var id in new[] { GuardianCheckIds.ClaudeProcess, GuardianCheckIds.ProxyClient,
                     GuardianCheckIds.VpnAdapter, GuardianCheckIds.Locale, GuardianCheckIds.ClientLanguage })
            MarkObserved(id, true);

        var connections = _nativeEvidence.CaptureConnections(processes, _cycleStartedAt);
        _observations[GuardianCheckIds.ActiveConnections] = connections.Observation;
        _observations[GuardianCheckIds.Ipv6] = routeTable.Observation;
        _udpEndpoints = connections.Udp;
        _connections = connections.Tcp.Select(endpoint =>
            $"{endpoint.ProcessId} [{endpoint.RemoteAddress}]:{endpoint.RemotePort}").ToArray();
        var ipv4Index = adapter is null ? -1 : GetIpv4InterfaceIndex(adapter);
        var ipv6Index = adapter is null ? -1 : GetIpv6InterfaceIndex(adapter);
        var ipv6Names = NetworkInterface.GetAllNetworkInterfaces()
            .GroupBy(GetIpv6InterfaceIndex).ToDictionary(group => group.Key, group => group.First().Name);
        _publicIpv6Routes = routeTable.Routes.Where(route =>
                route.Prefix.AddressFamily == AddressFamily.InterNetworkV6 && route.InterfaceIndex != ipv6Index &&
                IsPublicOrNat64Ipv6Prefix(route.Prefix.GetAddressBytes(), route.PrefixLength))
            .Select(route => ipv6Names.GetValueOrDefault(route.InterfaceIndex, $"ifIndex={route.InterfaceIndex}"))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        _routeContext = new(_nativeEvidence, ipv4Index, ipv6Index, proxy.Configured, new());
        ActiveProbeRoute.Value = _routeContext;
        foreach (var destination in new[] { "1.1.1.1", "8.8.8.8" }.Concat(
                     connections.Tcp.Select(endpoint => endpoint.RemoteAddress)).Concat(_lastProbeDestinations).Distinct())
        {
            if (!IPAddress.TryParse(destination, out var address) || IPAddress.IsLoopback(address)) continue;
            _routeContext.Results.Add(_nativeEvidence.InspectRoute(address,
                address.AddressFamily == AddressFamily.InterNetwork ? ipv4Index : ipv6Index));
        }
        _observations[GuardianCheckIds.DefaultRoute] = routeTable.Observation;
    }

    private bool EgressRefreshDue() => EvidenceFreshness.NeedsEgressRefresh(_clock.UtcNow,
        _observations.GetValueOrDefault(GuardianCheckIds.EgressIp), _lastIpv4Trace.Ip);

    private void InvalidateCachedEvidence()
    {
        _lastIpv4Trace = TraceResolution.Empty;
        _lastTunDirectTrace = TraceResolution.Empty;
        _lastIpv6Trace = TraceResolution.Empty;
        _lastTimezone = null;
        _lastStunResults = Array.Empty<StunResult>();
        _lastResolvedClaudeIps = Array.Empty<string>();
        _lastDnsDetail = "尚未采集";
        _lastClaudeHttps = new Dictionary<string, string>();
        _lastAsn = ("", "", "尚未采集");
        _lastClashAudit = null;
        _lastIpReputation = null;
        _lastIpReputationError = "网络上下文已变化，等待刷新";
        _lastProbeDestinations = Array.Empty<string>();
        _observations.Clear();
        _networkContext = "";
    }

    private void MarkObserved(string id, bool succeeded, string error = "")
    {
        _observations[id] = new(succeeded, _clock.UtcNow, succeeded ? "" : error);
    }

    private void MarkHelperEvidence(HelperStatusSnapshot helper)
    {
        MarkObserved(GuardianCheckIds.HelperService, helper.HelperAlive, helper.HelperDetail);
        MarkObserved(GuardianCheckIds.WfpPolicy, helper.HelperAlive && helper.WfpState is not (null or "unknown" or "unavailable"), helper.WfpDetail ?? "");
        MarkObserved(GuardianCheckIds.FirewallReadiness, helper.FirewallApiOk && helper.FirewallPolicyEffective is not null, helper.FirewallDetail);
        MarkObserved(GuardianCheckIds.TcpOnlyPolicy, helper.TcpOnlyState is "active" or "off" or "stale" or "invalid", helper.TcpOnlyDetail);
    }

    private static bool ValidIpv6Observation(TraceResolution trace) => !string.IsNullOrWhiteSpace(trace.Ip) ||
        trace.Detail.Contains("返回的地址不是 IPv6", StringComparison.OrdinalIgnoreCase);

    private NetworkSnapshot CompleteEvidence(NetworkSnapshot snapshot)
    {
        if (snapshot.HasIpv6 && _publicIpv6Routes.Count == 0 &&
            _observations.TryGetValue(GuardianCheckIds.Ipv6, out var routeObservation))
        {
            var exitObservation6 = _observations.GetValueOrDefault("ipv6-egress");
            _observations[GuardianCheckIds.Ipv6] = new(routeObservation.Succeeded && exitObservation6?.Succeeded == true,
                exitObservation6 is not null && exitObservation6.ObservedAt < routeObservation.ObservedAt
                    ? exitObservation6.ObservedAt : routeObservation.ObservedAt,
                !routeObservation.Succeeded ? routeObservation.Error : exitObservation6?.Error ?? "缺少 IPv6 出口证据",
                exitObservation6?.IsCached == true);
        }
        if (_observations.TryGetValue(GuardianCheckIds.EgressIp, out var exitObservation))
            _observations[GuardianCheckIds.IpConsistency] = exitObservation;
        DestinationRoute[] routes;
        lock (_routeContext?.Results ?? new List<DestinationRoute>())
            routes = _routeContext?.Results.ToArray() ?? Array.Empty<DestinationRoute>();
        _lastProbeDestinations = routes.Select(route => route.Destination).Distinct().ToArray();
        return snapshot with
        {
            Observations = new Dictionary<string, CollectionObservation>(_observations),
            CapturedAt = _clock.UtcNow,
            UdpEndpoints = _udpEndpoints,
            DestinationRoutes = routes,
            NetworkContext = _networkContext,
            ContextChanged = _contextChanged
        };
    }

    private static bool HasHttpResponses(GuardianConfig config, IReadOnlyDictionary<string, string> responses) =>
        config.EffectiveClaudeDomains.All(domain => responses.TryGetValue(domain, out var value) &&
            int.TryParse(value, out var status) && status is >= 100 and <= 599);

    private static void ValidateProbeRoute(IPAddress address, bool systemProxy)
    {
        var context = ActiveProbeRoute.Value;
        if (context is null) throw new HttpRequestException("尚未验证 TUN 路径");
        context.Validate(address, systemProxy);
    }
}
