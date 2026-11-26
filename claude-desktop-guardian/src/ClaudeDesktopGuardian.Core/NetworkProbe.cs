using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClaudeDesktopGuardian.Core;

public sealed record RegionAdaptProbeResult(
    bool Success,
    string Country,
    string IanaTimezone,
    string WindowsTimezone,
    string Locale,
    string Source,
    string Error);

public sealed class WindowsEnvironmentProbe : IEnvironmentProbe, ISingleCheckProbe
{
    private static readonly HttpClient Http = CreateHttpClient(AddressFamily.InterNetwork, useSystemProxy: true);
    private static readonly HttpClient DirectTunHttp = CreateHttpClient(AddressFamily.InterNetwork, useSystemProxy: false);
    private static readonly HttpClient Ipv6Http = CreateHttpClient(AddressFamily.InterNetworkV6, useSystemProxy: false);

    private readonly IpHistoryStore _ipHistoryStore;
    private readonly IpReputationService _ipReputationService;
    private readonly ClashInspector _clashInspector;
    private readonly Func<string, bool, CancellationToken, Task<string?>>? _wfpStatusProvider;
    private readonly Func<string, bool, CancellationToken, Task<HelperStatusSnapshot?>>? _helperStatusProvider;

    private TraceResolution _lastIpv4Trace = TraceResolution.Empty;
    private TraceResolution _lastTunDirectTrace = TraceResolution.Empty;
    private bool _lastSystemProxyConfigured;
    private string _lastSystemProxyUri = string.Empty;
    private TraceResolution _lastIpv6Trace = TraceResolution.Empty;
    private TimezoneResolution? _lastTimezone;
    private IReadOnlyList<StunResult> _lastStunResults = Array.Empty<StunResult>();
    private IReadOnlyList<string> _lastResolvedClaudeIps = Array.Empty<string>();
    private string _lastDnsDetail = string.Empty;
    private IReadOnlyDictionary<string, string> _lastClaudeHttps = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    private (string Org, string Type, string Detail) _lastAsn = (string.Empty, string.Empty, string.Empty);
    private ClashAuditResult? _lastClashAudit;
    private IpReputationRecord? _lastIpReputation;
    private string _lastIpReputationError = string.Empty;
    private int _lastIpDrift48h;
    private string _lastPreviousExitIp = string.Empty;

    public WindowsEnvironmentProbe(
        IpHistoryStore? ipHistoryStore = null,
        IpReputationService? ipReputationService = null,
        ClashInspector? clashInspector = null,
        Func<string, bool, CancellationToken, Task<string?>>? wfpStatusProvider = null,
        Func<string, bool, CancellationToken, Task<HelperStatusSnapshot?>>? helperStatusProvider = null)
    {
        _ipHistoryStore = ipHistoryStore ?? new IpHistoryStore();
        _ipReputationService = ipReputationService ?? new IpReputationService(Http);
        _clashInspector = clashInspector ?? new ClashInspector();
        _wfpStatusProvider = wfpStatusProvider;
        _helperStatusProvider = helperStatusProvider;
    }

    public async Task<RegionAdaptProbeResult> ProbeRegionForAdaptAsync(
        GuardianConfig config,
        CancellationToken cancellationToken)
    {
        var (_, proxyClientAlive, proxyDetail) = DetectProxyClient(config.ProxyClientMode);
        var (adapter, _, _, adapterDiag) = FindBestVpnAdapter(config);
        if (adapter is null || !proxyClientAlive)
        {
            return new RegionAdaptProbeResult(
                false,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                $"代理或 TUN 未就绪（{(proxyClientAlive ? adapterDiag : proxyDetail)}），已中止地区适配以防真实 IP 暴露");
        }

        var trace = await ProbeIpv4EgressMultiSourceAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(trace.Country))
        {
            return new RegionAdaptProbeResult(
                false,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                $"出口国家探测失败：{trace.Detail}");
        }

        var country = trace.Country.Trim().ToUpperInvariant();
        if (country == "CN")
        {
            return new RegionAdaptProbeResult(
                false,
                country,
                string.Empty,
                string.Empty,
                string.Empty,
                trace.Source,
                "出口国家为 CN，拒绝适配地区（请先切换非 CN 代理节点）");
        }

        var tz = await new ExitTimezoneResolver(Http).ResolveAsync(cancellationToken, country);
        var ianaTz = tz?.IanaId ?? CountryDefaults.GetDefaultIanaTimezone(country) ?? "America/New_York";
        var winTz = tz?.WindowsId ?? (WindowsTimezoneMapper.TryMap(ianaTz, out var mapped) ? mapped : "Eastern Standard Time");
        var locale = CountryDefaults.GetExpectedLocale(country);
        return new RegionAdaptProbeResult(true, country, ianaTz, winTz, locale, trace.Source, string.Empty);
    }

    public async Task<NetworkSnapshot> CaptureSingleCheckAsync(
        NetworkSnapshot previous,
        string checkId,
        GuardianConfig config,
        IReadOnlyList<ProcessInfo> protectedProcesses,
        CancellationToken cancellationToken)
    {
        var (proxyClientName, proxyClientAlive, proxyClientDetail) = DetectProxyClient(config.ProxyClientMode);
        var (adapter, isFakeIp, hasDefaultRoute, adapterDiagnostic) = FindBestVpnAdapter(config);

        var adapterGuid = adapter?.Id ?? string.Empty;
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
        var currentLocale = CultureInfo.CurrentCulture.Name;

        var hasAdapterIpv6 = HasIpv6Route(adapter);
        var publicIpv6Routes = InspectPublicIpv6Routes(adapter);
        var hasIpv6 = hasAdapterIpv6 || publicIpv6Routes.Count > 0;

        var helper = await QueryHelperAndWfpAsync(adapter, config, cancellationToken);
        var connections = CaptureConnections(protectedProcesses);
        var (clientLang, clientLangSource) = ReadClaudeClientLanguage();

        if (adapter is null || !proxyClientAlive)
        {
            return BuildSkippedSnapshot(
                config,
                adapter,
                localAddress,
                gateway,
                dnsServers,
                connections,
                hasIpv6,
                currentWindowsTimezone,
                adapterGuid,
                isFakeIp,
                hasDefaultRoute,
                adapterDiagnostic,
                proxyClientName,
                proxyClientAlive,
                proxyClientDetail,
                publicIpv6Routes,
                currentLocale,
                clientLang,
                clientLangSource,
                helper);
        }

        var snapshot = previous with
        {
            AdapterName = adapter.Name,
            AdapterDescription = adapter.Description,
            LocalAddress = localAddress,
            Gateway = gateway,
            DnsServers = dnsServers,
            ActiveConnections = connections,
            HasIpv6 = hasIpv6,
            CurrentWindowsTimezone = currentWindowsTimezone,
            AdapterGuid = adapterGuid,
            AdapterIsFakeIp = isFakeIp,
            AdapterHasDefaultRoute = hasDefaultRoute,
            AdapterDiagnostic = adapterDiagnostic,
            ProxyClientName = proxyClientName,
            ProxyClientAlive = proxyClientAlive,
            ProxyClientDetail = proxyClientDetail,
            ProxyPathSkipped = false,
            PublicIpv6Routes = publicIpv6Routes,
            CurrentLocale = currentLocale,
            ClientLanguage = clientLang,
            ClientLanguageSource = clientLangSource,
            WfpPolicyState = helper.WfpState ?? "unavailable",
            WfpPolicyDetail = helper.WfpDetail ?? string.Empty,
            HelperAlive = helper.HelperAlive,
            HelperDetail = helper.HelperDetail,
            FirewallApiOk = helper.FirewallApiOk,
            FirewallActiveRuleCount = helper.FirewallActiveRuleCount,
            FirewallDetail = helper.FirewallDetail
        };

        var normalizedId = checkId.Trim().ToLowerInvariant();
        if (config.IsCheckDisabled(normalizedId))
        {
            return snapshot;
        }

        switch (normalizedId)
        {
            case GuardianCheckIds.EgressIp:
            case GuardianCheckIds.IpConsistency:
            {
                var (sysProxyOn, sysProxyUri) = DetectSystemProxy();
                _lastSystemProxyConfigured = sysProxyOn;
                _lastSystemProxyUri = sysProxyUri;

                var traceTask = ProbeIpv4EgressMultiSourceAsync(Http, cancellationToken);
                var tunDirectTask = sysProxyOn
                    ? ProbeIpv4EgressMultiSourceAsync(DirectTunHttp, cancellationToken)
                    : Task.FromResult(TraceResolution.Empty);
                var trace = await traceTask;
                var tunDirect = await tunDirectTask;
                _lastIpv4Trace = trace;
                _lastTunDirectTrace = tunDirect;
                if (!config.IsCheckDisabled(GuardianCheckIds.IpConsistency) && !string.IsNullOrWhiteSpace(trace.Ip))
                {
                    var (prevIp, uniqueCount) = _ipHistoryStore.RecordAndInspect(trace.Ip, DateTimeOffset.UtcNow);
                    _lastPreviousExitIp = prevIp;
                    _lastIpDrift48h = uniqueCount;
                }

                var expectedLocale = !string.IsNullOrWhiteSpace(config.ExpectedLocale)
                    ? config.ExpectedLocale
                    : CountryDefaults.GetExpectedLocale(
                        !string.IsNullOrWhiteSpace(config.ExpectedExitCountry)
                            ? config.ExpectedExitCountry
                            : trace.Country);
                snapshot = snapshot with
                {
                    ExitIp = trace.Ip,
                    ExitCountry = trace.Country,
                    Ipv4ProbeDetail = trace.Detail,
                    ExitIpSource = trace.Source,
                    ExpectedLocale = expectedLocale,
                    IpDriftCount48h = _lastIpDrift48h,
                    PreviousExitIp = _lastPreviousExitIp,
                    SystemProxyConfigured = sysProxyOn,
                    SystemProxyUri = sysProxyUri,
                    TunDirectExitIp = tunDirect.Ip,
                    TunDirectExitCountry = tunDirect.Country,
                    TunDirectProbeDetail = tunDirect.Detail
                };
                break;
            }
            case GuardianCheckIds.Timezone:
            {
                var country = !string.IsNullOrWhiteSpace(snapshot.ExitCountry)
                    ? snapshot.ExitCountry
                    : config.ExpectedExitCountry;
                var tz = await new ExitTimezoneResolver(Http).ResolveAsync(cancellationToken, country);
                if (tz is null && hasAdapterIpv6)
                {
                    tz = await new ExitTimezoneResolver(Ipv6Http).ResolveAsync(cancellationToken, country);
                }

                if (tz is not null)
                {
                    _lastTimezone = tz;
                }

                snapshot = snapshot with
                {
                    ExitTimezone = tz?.IanaId ?? string.Empty,
                    ExitWindowsTimezone = tz?.WindowsId ?? string.Empty
                };
                break;
            }
            case GuardianCheckIds.Dns:
            {
                var (resolvedIps, dnsDetail) = await ProbeClaudeDnsAsync(cancellationToken);
                _lastResolvedClaudeIps = resolvedIps;
                _lastDnsDetail = dnsDetail;
                snapshot = snapshot with
                {
                    ResolvedClaudeIps = resolvedIps,
                    DnsProbeDetail = dnsDetail
                };
                break;
            }
            case GuardianCheckIds.Ipv6:
            {
                var v6 = hasAdapterIpv6
                    ? await TryGetCloudflareTraceAsync(Ipv6Http, AddressFamily.InterNetworkV6, cancellationToken)
                    : TraceResolution.Empty;
                _lastIpv6Trace = v6;
                snapshot = snapshot with
                {
                    ExitIpv6 = v6.Ip,
                    ExitIpv6Country = v6.Country,
                    Ipv6ProbeDetail = v6.Detail
                };
                break;
            }
            case GuardianCheckIds.WebRtc:
            {
                if (string.IsNullOrWhiteSpace(snapshot.ExitIp))
                {
                    var trace = await ProbeIpv4EgressMultiSourceAsync(cancellationToken);
                    _lastIpv4Trace = trace;
                    snapshot = snapshot with
                    {
                        ExitIp = trace.Ip,
                        ExitCountry = trace.Country,
                        Ipv4ProbeDetail = trace.Detail,
                        ExitIpSource = trace.Source
                    };
                }

                var stun = await ProbeStunAsync(config.EffectiveStunServers, hasAdapterIpv6, cancellationToken);
                _lastStunResults = stun;
                snapshot = snapshot with { StunResults = stun };
                break;
            }
            case GuardianCheckIds.ClashRules:
            {
                var clash = await _clashInspector.InspectAsync(config, cancellationToken);
                _lastClashAudit = clash;
                snapshot = snapshot with
                {
                    ClashMode = clash.Mode,
                    ClashRulesStatus = clash.Status,
                    ClashRulesDetail = clash.Detail,
                    ClashRulesLoaded = clash.PinnedRulesLoaded
                };
                break;
            }
            case GuardianCheckIds.Asn:
            {
                var exitIp = snapshot.ExitIp;
                if (string.IsNullOrWhiteSpace(exitIp))
                {
                    var trace = await ProbeIpv4EgressMultiSourceAsync(cancellationToken);
                    _lastIpv4Trace = trace;
                    exitIp = trace.Ip;
                    snapshot = snapshot with
                    {
                        ExitIp = trace.Ip,
                        ExitCountry = trace.Country,
                        Ipv4ProbeDetail = trace.Detail,
                        ExitIpSource = trace.Source
                    };
                }

                if (!string.IsNullOrWhiteSpace(exitIp))
                {
                    var asn = await ProbeAsnAsync(exitIp, cancellationToken);
                    _lastAsn = asn;
                    snapshot = snapshot with { AsnOrg = asn.Org, AsnType = asn.Type, AsnDetail = asn.Detail };
                }

                break;
            }
            case GuardianCheckIds.ClaudeDomains:
            {
                var https = await ProbeClaudeHttpsAsync(config.EffectiveClaudeDomains, cancellationToken);
                _lastClaudeHttps = https;
                snapshot = snapshot with { ClaudeHttps = https };
                break;
            }
            case GuardianCheckIds.IpRepScore:
            case GuardianCheckIds.IpRepProxy:
            case GuardianCheckIds.IpRepHosting:
            case GuardianCheckIds.IpRepBlacklist:
            {
                var exitIp = snapshot.ExitIp;
                if (string.IsNullOrWhiteSpace(exitIp))
                {
                    var trace = await ProbeIpv4EgressMultiSourceAsync(cancellationToken);
                    _lastIpv4Trace = trace;
                    exitIp = trace.Ip;
                    snapshot = snapshot with
                    {
                        ExitIp = trace.Ip,
                        ExitCountry = trace.Country,
                        Ipv4ProbeDetail = trace.Detail,
                        ExitIpSource = trace.Source
                    };
                }

                if (config.IpReputation is not null && !string.IsNullOrWhiteSpace(config.IpReputation.Url) && !string.IsNullOrWhiteSpace(exitIp))
                {
                    var (rec, err) = await _ipReputationService.LookupAsync(exitIp, config.IpReputation, DateTimeOffset.UtcNow, cancellationToken);
                    _lastIpReputation = rec;
                    _lastIpReputationError = err;
                    snapshot = snapshot with { IpReputation = rec, IpReputationError = err };
                }

                break;
            }
        }

        return snapshot;
    }

    public async Task<NetworkSnapshot> CaptureNetworkAsync(
        GuardianConfig config,
        IReadOnlyList<ProcessInfo> protectedProcesses,
        bool full,
        CancellationToken cancellationToken)
    {
        var (proxyClientName, proxyClientAlive, proxyClientDetail) = DetectProxyClient(config.ProxyClientMode);
        var (adapter, isFakeIp, hasDefaultRoute, adapterDiagnostic) = FindBestVpnAdapter(config);

        var adapterGuid = adapter?.Id ?? string.Empty;
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
        var currentLocale = CultureInfo.CurrentCulture.Name;

        var hasAdapterIpv6 = HasIpv6Route(adapter);
        var publicIpv6Routes = InspectPublicIpv6Routes(adapter);
        var hasIpv6 = hasAdapterIpv6 || publicIpv6Routes.Count > 0;

        var helper = await QueryHelperAndWfpAsync(adapter, config, cancellationToken);
        var connections = CaptureConnections(protectedProcesses);
        var (clientLang, clientLangSource) = ReadClaudeClientLanguage();

        // Strict path gate: NEVER issue external probes if proxy client or TUN adapter is offline!
        if (adapter is null || !proxyClientAlive)
        {
            return BuildSkippedSnapshot(
                config,
                adapter,
                localAddress,
                gateway,
                dnsServers,
                connections,
                hasIpv6,
                currentWindowsTimezone,
                adapterGuid,
                isFakeIp,
                hasDefaultRoute,
                adapterDiagnostic,
                proxyClientName,
                proxyClientAlive,
                proxyClientDetail,
                publicIpv6Routes,
                currentLocale,
                clientLang,
                clientLangSource,
                helper);
        }

        // Detect whether Windows/environment system HTTP proxy is enabled
        var (systemProxyConfigured, systemProxyUri) = DetectSystemProxy();
        _lastSystemProxyConfigured = systemProxyConfigured;
        _lastSystemProxyUri = systemProxyUri;

        // Run network probes through the verified active VPN/TUN path
        var runIpv4 = full || string.IsNullOrWhiteSpace(_lastIpv4Trace.Ip);
        var traceTask = runIpv4
            ? ProbeIpv4EgressMultiSourceAsync(Http, cancellationToken)
            : Task.FromResult(_lastIpv4Trace);

        var tunDirectTask = !systemProxyConfigured
            ? Task.FromResult(TraceResolution.Empty)
            : runIpv4 || string.IsNullOrWhiteSpace(_lastTunDirectTrace.Ip)
                ? ProbeIpv4EgressMultiSourceAsync(DirectTunHttp, cancellationToken)
                : Task.FromResult(_lastTunDirectTrace);

        var ipv6TraceTask = !full
            ? Task.FromResult(_lastIpv6Trace)
            : hasAdapterIpv6
                ? TryGetCloudflareTraceAsync(Ipv6Http, AddressFamily.InterNetworkV6, cancellationToken)
                : Task.FromResult(TraceResolution.Empty);

        var runStun = !config.IsCheckDisabled(GuardianCheckIds.WebRtc) &&
                      (full || _lastStunResults.Count == 0);
        var stunTask = config.IsCheckDisabled(GuardianCheckIds.WebRtc)
            ? Task.FromResult<IReadOnlyList<StunResult>>(Array.Empty<StunResult>())
            : runStun
                ? ProbeStunAsync(config.EffectiveStunServers, hasAdapterIpv6, cancellationToken)
                : Task.FromResult(_lastStunResults);

        var dnsTask = full && !config.IsCheckDisabled(GuardianCheckIds.Dns)
            ? ProbeClaudeDnsAsync(cancellationToken)
            : Task.FromResult((_lastResolvedClaudeIps, _lastDnsDetail));

        var claudeTask = full && !config.IsCheckDisabled(GuardianCheckIds.ClaudeDomains)
            ? ProbeClaudeHttpsAsync(config.EffectiveClaudeDomains, cancellationToken)
            : Task.FromResult(_lastClaudeHttps);

        Task<ClashAuditResult?> clashTask = full && !config.IsCheckDisabled(GuardianCheckIds.ClashRules)
            ? InspectClashNullableAsync(config, cancellationToken)
            : Task.FromResult(_lastClashAudit);

        var trace = await traceTask;
        if (runIpv4)
        {
            _lastIpv4Trace = trace;
        }

        var tunDirectTrace = await tunDirectTask;
        _lastTunDirectTrace = systemProxyConfigured ? tunDirectTrace : TraceResolution.Empty;

        var ipv6Trace = await ipv6TraceTask;
        if (full)
        {
            _lastIpv6Trace = ipv6Trace;
        }

        var (resolvedClaudeIps, dnsProbeDetail) = await dnsTask;
        if (full && !config.IsCheckDisabled(GuardianCheckIds.Dns))
        {
            _lastResolvedClaudeIps = resolvedClaudeIps;
            _lastDnsDetail = dnsProbeDetail;
        }

        var stunResults = await stunTask;
        if (runStun)
        {
            _lastStunResults = stunResults;
        }

        var claudeHttps = await claudeTask;
        if (full && !config.IsCheckDisabled(GuardianCheckIds.ClaudeDomains))
        {
            _lastClaudeHttps = claudeHttps;
        }

        var clashAudit = await clashTask;
        if (full && !config.IsCheckDisabled(GuardianCheckIds.ClashRules))
        {
            _lastClashAudit = clashAudit;
        }

        // Timezone resolution
        var timezone = _lastTimezone;
        if (full)
        {
            timezone = await new ExitTimezoneResolver(Http).ResolveAsync(cancellationToken, trace.Country);
            if (timezone is null && hasAdapterIpv6)
            {
                timezone = await new ExitTimezoneResolver(Ipv6Http).ResolveAsync(cancellationToken, trace.Country);
            }

            if (timezone is not null)
            {
                _lastTimezone = timezone;
            }
        }

        // 48h IP drift tracking (only if ip-consistency enabled and we have an exit IP)
        if (full && !config.IsCheckDisabled(GuardianCheckIds.IpConsistency) && !string.IsNullOrWhiteSpace(trace.Ip))
        {
            var (prevIp, uniqueCount) = _ipHistoryStore.RecordAndInspect(trace.Ip, DateTimeOffset.UtcNow);
            _lastPreviousExitIp = prevIp;
            _lastIpDrift48h = uniqueCount;
        }

        // ASN & IP Reputation (run in parallel on full check, only when enabled & path still alive)
        var asnResult = _lastAsn;
        var ipRepRecord = _lastIpReputation;
        var ipRepError = _lastIpReputationError;

        if (full && !string.IsNullOrWhiteSpace(trace.Ip))
        {
            var runAsn = !config.IsCheckDisabled(GuardianCheckIds.Asn);
            var runRep = config.IpReputation is not null &&
                         !string.IsNullOrWhiteSpace(config.IpReputation.Url) &&
                         GuardianCheckIds.IpReputationIds.Any(id => !config.IsCheckDisabled(id));

            var asnTask = runAsn
                ? ProbeAsnAsync(trace.Ip, cancellationToken)
                : Task.FromResult(_lastAsn);

            var repTask = runRep
                ? _ipReputationService.LookupAsync(trace.Ip, config.IpReputation!, DateTimeOffset.UtcNow, cancellationToken)
                : Task.FromResult<(IpReputationRecord?, string)>((null,
                    config.IpReputation is null || string.IsNullOrWhiteSpace(config.IpReputation.Url)
                        ? "未配置信誉数据源"
                        : string.Empty));

            if (runAsn)
            {
                asnResult = await asnTask;
                _lastAsn = asnResult;
            }

            (ipRepRecord, ipRepError) = await repTask;
            _lastIpReputation = ipRepRecord;
            _lastIpReputationError = ipRepError;
        }

        var expectedLocale = !string.IsNullOrWhiteSpace(config.ExpectedLocale)
            ? config.ExpectedLocale
            : CountryDefaults.GetExpectedLocale(
                !string.IsNullOrWhiteSpace(config.ExpectedExitCountry)
                    ? config.ExpectedExitCountry
                    : trace.Country);

        return new NetworkSnapshot(
            adapter.Name,
            adapter.Description,
            localAddress,
            gateway,
            trace.Ip,
            trace.Country,
            ipv6Trace.Ip,
            ipv6Trace.Country,
            dnsServers,
            stunResults,
            connections,
            hasIpv6,
            claudeHttps,
            timezone?.IanaId ?? string.Empty,
            timezone?.WindowsId ?? string.Empty,
            currentWindowsTimezone,
            ipv6Trace.Detail,
            trace.Detail,
            null,
            adapterGuid,
            isFakeIp,
            hasDefaultRoute,
            adapterDiagnostic,
            proxyClientName,
            proxyClientAlive,
            proxyClientDetail,
            trace.Source,
            ProxyPathSkipped: false,
            ResolvedClaudeIps: resolvedClaudeIps,
            DnsProbeDetail: dnsProbeDetail,
            PublicIpv6Routes: publicIpv6Routes,
            CurrentLocale: currentLocale,
            ExpectedLocale: expectedLocale,
            ClientLanguage: clientLang,
            ClientLanguageSource: clientLangSource,
            AsnOrg: asnResult.Org,
            AsnType: asnResult.Type,
            AsnDetail: asnResult.Detail,
            ClashMode: clashAudit?.Mode ?? string.Empty,
            ClashRulesStatus: clashAudit?.Status ?? string.Empty,
            ClashRulesDetail: clashAudit?.Detail ?? string.Empty,
            ClashRulesLoaded: clashAudit?.PinnedRulesLoaded,
            WfpPolicyState: helper.WfpState ?? "unavailable",
            WfpPolicyDetail: helper.WfpDetail ?? string.Empty,
            IpReputation: ipRepRecord,
            IpReputationError: ipRepError,
            IpDriftCount48h: _lastIpDrift48h,
            PreviousExitIp: _lastPreviousExitIp,
            HelperAlive: helper.HelperAlive,
            HelperDetail: helper.HelperDetail,
            FirewallApiOk: helper.FirewallApiOk,
            FirewallActiveRuleCount: helper.FirewallActiveRuleCount,
            FirewallDetail: helper.FirewallDetail,
            SystemProxyConfigured: systemProxyConfigured,
            SystemProxyUri: systemProxyUri,
            TunDirectExitIp: tunDirectTrace.Ip,
            TunDirectExitCountry: tunDirectTrace.Country,
            TunDirectProbeDetail: tunDirectTrace.Detail);
    }

    private NetworkSnapshot BuildSkippedSnapshot(
        GuardianConfig config,
        NetworkInterface? adapter,
        string localAddress,
        string gateway,
        string[] dnsServers,
        IReadOnlyList<string> connections,
        bool hasIpv6,
        string currentWindowsTimezone,
        string adapterGuid,
        bool isFakeIp,
        bool hasDefaultRoute,
        string adapterDiagnostic,
        string proxyClientName,
        bool proxyClientAlive,
        string proxyClientDetail,
        IReadOnlyList<string> publicIpv6Routes,
        string currentLocale,
        string clientLang,
        string clientLangSource,
        HelperStatusSnapshot helper)
    {
        var fallbackExpectedLocale = !string.IsNullOrWhiteSpace(config.ExpectedLocale)
            ? config.ExpectedLocale
            : CountryDefaults.GetExpectedLocale(config.ExpectedExitCountry);

        return new NetworkSnapshot(
            adapter?.Name ?? string.Empty,
            adapter?.Description ?? string.Empty,
            localAddress,
            gateway,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            dnsServers,
            Array.Empty<StunResult>(),
            connections,
            hasIpv6,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            string.Empty,
            string.Empty,
            currentWindowsTimezone,
            string.Empty,
            "代理路径不可用，已跳过外网探测（避免真实 IP 直连暴露）",
            null,
            adapterGuid,
            isFakeIp,
            hasDefaultRoute,
            adapterDiagnostic,
            proxyClientName,
            proxyClientAlive,
            proxyClientDetail,
            string.Empty,
            ProxyPathSkipped: true,
            ResolvedClaudeIps: Array.Empty<string>(),
            DnsProbeDetail: "代理路径不可用，已跳过 DNS 探测",
            PublicIpv6Routes: publicIpv6Routes,
            CurrentLocale: currentLocale,
            ExpectedLocale: fallbackExpectedLocale,
            ClientLanguage: clientLang,
            ClientLanguageSource: clientLangSource,
            AsnOrg: string.Empty,
            AsnType: string.Empty,
            AsnDetail: "代理路径不可用，已跳过 ASN 查询",
            ClashMode: _lastClashAudit?.Mode ?? string.Empty,
            ClashRulesStatus: _lastClashAudit?.Status ?? string.Empty,
            ClashRulesDetail: _lastClashAudit?.Detail ?? string.Empty,
            ClashRulesLoaded: _lastClashAudit?.PinnedRulesLoaded,
            WfpPolicyState: helper.WfpState ?? "unavailable",
            WfpPolicyDetail: helper.WfpDetail ?? string.Empty,
            IpReputation: null,
            IpReputationError: "代理路径失效，已跳过信誉探测",
            IpDriftCount48h: _lastIpDrift48h,
            PreviousExitIp: _lastPreviousExitIp,
            HelperAlive: helper.HelperAlive,
            HelperDetail: helper.HelperDetail,
            FirewallApiOk: helper.FirewallApiOk,
            FirewallActiveRuleCount: helper.FirewallActiveRuleCount,
            FirewallDetail: helper.FirewallDetail);
    }

    public static (string ClientName, bool Alive, string Detail) DetectProxyClient(string proxyClientMode)
    {
        var mode = ProxyClientModes.Normalize(proxyClientMode);
        var display = ProxyClientModes.DisplayName(mode);

        if (mode == ProxyClientModes.Other)
        {
            return (display, true, "按配置仅校验 VPN/TUN 网卡");
        }

        static bool HasAnyProcess(params string[] names)
        {
            foreach (var name in names)
            {
                try
                {
                    if (Process.GetProcessesByName(name).Length > 0)
                    {
                        return true;
                    }
                }
                catch
                {
                }
            }

            return false;
        }

        static bool HasRunningWireGuardService()
        {
            if (!OperatingSystem.IsWindows())
            {
                return false;
            }

            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name, State FROM Win32_Service WHERE Name LIKE 'WireGuardTunnel%'");
                foreach (var obj in searcher.Get())
                {
                    var state = obj["State"]?.ToString();
                    if (string.Equals(state, "Running", StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }
            catch
            {
            }

            return false;
        }

        switch (mode)
        {
            case ProxyClientModes.ClashVerge:
                return HasAnyProcess("verge-mihomo", "clash-verge")
                    ? (display, true, "verge-mihomo 运行中")
                    : (display, false, "Clash Verge 内核（verge-mihomo）未运行");
            case ProxyClientModes.FlClash:
                return HasAnyProcess("FlClashCore", "FlClash")
                    ? (display, true, "FlClash 内核运行中")
                    : (display, false, "FlClashCore / FlClash 未运行");
            case ProxyClientModes.SingBox:
                return HasAnyProcess("sing-box")
                    ? (display, true, "sing-box 运行中")
                    : (display, false, "sing-box 未运行");
            case ProxyClientModes.ClashX:
                return HasAnyProcess("ClashX")
                    ? (display, true, "ClashX 运行中")
                    : (display, false, "ClashX 未运行");
            case ProxyClientModes.Surge:
                return HasAnyProcess("Surge")
                    ? (display, true, "Surge 运行中")
                    : (display, false, "Surge 未运行");
            case ProxyClientModes.WireGuard:
                return HasRunningWireGuardService()
                    ? (display, true, "WireGuardTunnel 服务运行中")
                    : (display, false, "WireGuardTunnel 服务未运行");
            default: // auto
                if (HasAnyProcess("verge-mihomo")) return ("Clash Verge", true, "自动识别：verge-mihomo 运行中");
                if (HasAnyProcess("FlClashCore", "FlClash")) return ("FlClash", true, "自动识别：FlClash 运行中");
                if (HasAnyProcess("sing-box")) return ("sing-box", true, "自动识别：sing-box 运行中");
                if (HasAnyProcess("ClashX")) return ("ClashX", true, "自动识别：ClashX 运行中");
                if (HasAnyProcess("Surge")) return ("Surge", true, "自动识别：Surge 运行中");
                if (HasRunningWireGuardService()) return ("WireGuard", true, "自动识别：WireGuard 服务运行中");
                // In auto mode, fall back to TUN-only verification so custom VPNs (Tailscale/Astrill/OpenVPN) aren't false-killed
                return ("自动识别（仅 TUN）", true, "未检测到已知代理内核进程，将按在线 VPN/TUN 网卡校验");
        }
    }

    public static (NetworkInterface? Adapter, bool IsFakeIp, bool HasDefaultRoute, string Diagnostic) FindBestVpnAdapter(
        GuardianConfig config)
    {
        var interfaces = NetworkInterface.GetAllNetworkInterfaces()
            .Where(item => item.OperationalStatus == OperationalStatus.Up)
            .Where(item => item.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .ToArray();

        IEnumerable<NetworkInterface> matched;
        if (!string.IsNullOrWhiteSpace(config.VpnAdapterPattern))
        {
            matched = interfaces.Where(item =>
                item.Name.Contains(config.VpnAdapterPattern, StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains(config.VpnAdapterPattern, StringComparison.OrdinalIgnoreCase));
        }
        else
        {
            matched = interfaces.Where(item =>
                item.Description.Contains("Meta Tunnel", StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains("Mihomo", StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains("Clash", StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains("TUN", StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains("TAP", StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains("Wintun", StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains("VPN", StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains("Tailscale", StringComparison.OrdinalIgnoreCase) ||
                HasFakeIpAddress(item));
        }

        var candidates = matched
            .Where(HasValidIpv4Address)
            .ToArray();

        if (candidates.Length == 0)
        {
            var clashDiag = ClashInspector.ReadClashVergeTunDiagnostic(config.ProxyClientMode);
            var diagnostic = !string.IsNullOrEmpty(clashDiag)
                ? clashDiag
                : matched.Any()
                    ? "检测到虚拟网卡，但没有有效 IPv4 地址"
                    : "没有识别到在线 VPN/TUN 网卡";
            return (null, false, false, diagnostic);
        }

        var defaultRouteIfIndexes = GetIpv4DefaultRouteInterfaceIndexes();

        // Priority 1: 198.18.* Fake-IP TUN adapter (prefer one with IPv4 default route)
        var fakeIpAdapters = candidates.Where(HasFakeIpAddress).ToArray();
        var chosen = fakeIpAdapters.FirstOrDefault(a => defaultRouteIfIndexes.Contains(GetIpv4InterfaceIndex(a)))
                     ?? fakeIpAdapters.FirstOrDefault()
                     ?? candidates.FirstOrDefault(a => defaultRouteIfIndexes.Contains(GetIpv4InterfaceIndex(a)))
                     ?? candidates[0];

        var isFakeIp = HasFakeIpAddress(chosen);
        var ifIndex = GetIpv4InterfaceIndex(chosen);
        var hasGateway = chosen.GetIPProperties().GatewayAddresses
            .Any(gw => gw.Address.AddressFamily == AddressFamily.InterNetwork);
        var hasDefaultRoute = defaultRouteIfIndexes.Contains(ifIndex) || hasGateway;

        return (chosen, isFakeIp, hasDefaultRoute, isFakeIp ? "198.18 假 IP 段 TUN" : "通用虚拟网卡");
    }

    private static bool HasFakeIpAddress(NetworkInterface item) =>
        item.GetIPProperties().UnicastAddresses.Any(addr =>
            addr.Address.AddressFamily == AddressFamily.InterNetwork &&
            addr.Address.ToString().StartsWith("198.18.", StringComparison.Ordinal));

    private static bool HasValidIpv4Address(NetworkInterface item) =>
        item.GetIPProperties().UnicastAddresses.Any(addr =>
            addr.Address.AddressFamily == AddressFamily.InterNetwork &&
            !addr.Address.ToString().StartsWith("169.254.", StringComparison.Ordinal));

    private static int GetIpv4InterfaceIndex(NetworkInterface item)
    {
        try
        {
            return item.GetIPProperties().GetIPv4Properties()?.Index ?? -1;
        }
        catch
        {
            return -1;
        }
    }

    private async Task<ClashAuditResult?> InspectClashNullableAsync(
        GuardianConfig config,
        CancellationToken cancellationToken) =>
        await _clashInspector.InspectAsync(config, cancellationToken);

    private async Task<HelperStatusSnapshot> QueryHelperAndWfpAsync(
        NetworkInterface? adapter,
        GuardianConfig config,
        CancellationToken cancellationToken)
    {
        if (_helperStatusProvider is not null)
        {
            try
            {
                var helperStatus = await _helperStatusProvider(adapter?.Id ?? string.Empty, config.WfpAllowLoopback, cancellationToken);
                if (helperStatus is not null)
                {
                    var wfpState = string.IsNullOrWhiteSpace(helperStatus.WfpState)
                        ? (await QueryWfpStateDirectAsync(adapter, config)).State
                        : helperStatus.WfpState;
                    var wfpDetail = !string.IsNullOrWhiteSpace(helperStatus.WfpDetail)
                        ? helperStatus.WfpDetail
                        : FormatWfpDetail(wfpState, config.WfpStrictEnabled, config.WfpAllowLoopback);
                    return helperStatus with { WfpState = wfpState, WfpDetail = wfpDetail };
                }
            }
            catch
            {
            }
        }

        var (directState, directDetail) = await QueryWfpStateAsync(adapter, config, cancellationToken);
        return new HelperStatusSnapshot(
            HelperAlive: _helperStatusProvider is null,
            HelperDetail: _helperStatusProvider is null
                ? "受限命名管道在线"
                : "管理员助手命名管道无响应",
            WfpState: directState,
            WfpDetail: directDetail,
            FirewallApiOk: _helperStatusProvider is null,
            FirewallActiveRuleCount: 0,
            FirewallDetail: _helperStatusProvider is null
                ? "防火墙控制就绪"
                : "管理员助手离线，无法核验防火墙规则");
    }

    private async Task<(string State, string Detail)> QueryWfpStateAsync(
        NetworkInterface? adapter,
        GuardianConfig config,
        CancellationToken cancellationToken)
    {
        if (_wfpStatusProvider is not null)
        {
            try
            {
                var raw = await _wfpStatusProvider(adapter?.Id ?? string.Empty, config.WfpAllowLoopback, cancellationToken);
                if (!string.IsNullOrWhiteSpace(raw))
                {
                    return (raw, FormatWfpDetail(raw, config.WfpStrictEnabled, config.WfpAllowLoopback));
                }
            }
            catch
            {
            }
        }

        return await QueryWfpStateDirectAsync(adapter, config);
    }

    private static Task<(string State, string Detail)> QueryWfpStateDirectAsync(
        NetworkInterface? adapter,
        GuardianConfig config)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(("off", "非 Windows 环境"));
        }

        try
        {
            using var policy = new WfpNetworkPolicy();
            if (policy.Status(null, Array.Empty<string>(), 0, config.WfpAllowLoopback) == "off")
            {
                return Task.FromResult(("off", FormatWfpDetail("off", config.WfpStrictEnabled, config.WfpAllowLoopback)));
            }

            if (adapter is null || !Guid.TryParse(adapter.Id, out var guid))
            {
                return Task.FromResult(("stale", "已写入 WFP 规则，但当前未识别到匹配 TUN 接口"));
            }

            var install = ClaudeInstallDiscovery.Discover();
            var luid = WfpNetworkPolicy.InterfaceLuid(guid);
            var status = policy.Status(install.PackageFamilyName, install.ExecutablePaths, luid, config.WfpAllowLoopback);
            return Task.FromResult((status, FormatWfpDetail(status, config.WfpStrictEnabled, config.WfpAllowLoopback)));
        }
        catch
        {
            return Task.FromResult(("unavailable", "无法直接读取 WFP 状态（请确认管理员助手在线）"));
        }
    }

    private static string FormatWfpDetail(string state, bool strictEnabled, bool allowLoopback) => state switch
    {
        "active" => allowLoopback
            ? "WFP 内核出站白名单已生效（仅允许指定 TUN + 回环）"
            : "WFP 内核出站白名单已生效（仅允许指定 TUN，拦截直连与回环）",
        "stale" => "WFP 规则已过期（Claude 路径、TUN 接口或回环策略已变化），请刷新 WFP 规则",
        "off" => strictEnabled
            ? "已开启 WFP 严格模式但规则尚未生效，请点击启用/刷新 WFP 出站锁"
            : "未启用 WFP 内核出站锁（当前由防火墙急停 + 进程监控守护）",
        _ => "无法验证 WFP 内核策略状态"
    };

    public static (bool Configured, string RedactedProxyUri) DetectSystemProxy(Uri? probeUri = null)
    {
        try
        {
            var target = probeUri ?? new Uri("https://www.cloudflare.com/cdn-cgi/trace");
            var proxy = WebRequest.GetSystemWebProxy();
            if (proxy is null || proxy.IsBypassed(target))
            {
                return (false, string.Empty);
            }

            var resolved = proxy.GetProxy(target);
            if (resolved is null || Uri.Compare(resolved, target, UriComponents.SchemeAndServer, UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase) == 0)
            {
                return (false, string.Empty);
            }

            return (true, $"{resolved.Scheme}://{resolved.Host}:{resolved.Port}");
        }
        catch
        {
            return (false, string.Empty);
        }
    }

    private static Task<TraceResolution> ProbeIpv4EgressMultiSourceAsync(CancellationToken cancellationToken) =>
        ProbeIpv4EgressMultiSourceAsync(Http, cancellationToken);

    private static async Task<TraceResolution> ProbeIpv4EgressMultiSourceAsync(
        HttpClient client,
        CancellationToken cancellationToken)
    {
        var diagnostics = new List<string>();

        // 1. Cloudflare trace (2 attempts)
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var cf = await TryGetCloudflareTraceAsync(client, AddressFamily.InterNetwork, cancellationToken);
            if (!string.IsNullOrWhiteSpace(cf.Ip) && !string.IsNullOrWhiteSpace(cf.Country))
            {
                return cf;
            }

            if (attempt == 1 && !string.IsNullOrWhiteSpace(cf.Detail))
            {
                diagnostics.Add($"cloudflare: {cf.Detail}");
            }
            else if (attempt == 0)
            {
                await Task.Delay(350, cancellationToken);
            }
        }

        // 2. Fallback JSON endpoints: ipinfo -> ipwho.is -> api.ip.sb
        var jsonSources = new[]
        {
            ("ipinfo.io", "https://ipinfo.io/json", "ip", new[] { "country" }),
            ("ipwho.is", "https://ipwho.is/", "ip", new[] { "country_code", "country" }),
            ("api.ip.sb", "https://api.ip.sb/geoip", "ip", new[] { "country_code", "country" })
        };

        foreach (var (name, url, ipField, countryFields) in jsonSources)
        {
            for (var attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, url);
                    request.Headers.UserAgent.ParseAdd("ClaudeDesktopGuardian/2.0");
                    using var response = await client.SendAsync(request, cancellationToken);
                    if (!response.IsSuccessStatusCode)
                    {
                        if (attempt == 1) diagnostics.Add($"{name}: HTTP {(int)response.StatusCode}");
                        continue;
                    }

                    var body = await response.Content.ReadAsStringAsync(cancellationToken);
                    using var doc = JsonDocument.Parse(body);
                    var ip = doc.RootElement.TryGetProperty(ipField, out var ipProp)
                        ? ipProp.GetString()?.Trim() ?? string.Empty
                        : string.Empty;
                    var country = string.Empty;
                    foreach (var cfField in countryFields)
                    {
                        if (doc.RootElement.TryGetProperty(cfField, out var cProp) &&
                            cProp.ValueKind == JsonValueKind.String)
                        {
                            country = cProp.GetString()?.Trim().ToUpperInvariant() ?? string.Empty;
                            if (country.Length == 2)
                            {
                                break;
                            }
                        }
                    }

                    if (IPAddress.TryParse(ip, out var parsed) &&
                        parsed.AddressFamily == AddressFamily.InterNetwork &&
                        Regex.IsMatch(country, "^[A-Z]{2}$"))
                    {
                        return new TraceResolution(ip, country, string.Empty, name);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
                {
                    if (attempt == 1)
                    {
                        diagnostics.Add($"{name}: {ex.GetType().Name}");
                    }
                    else
                    {
                        await Task.Delay(350, cancellationToken);
                    }
                }
            }
        }

        return new TraceResolution(
            string.Empty,
            string.Empty,
            diagnostics.Count == 0 ? "多源出口探测均失败" : string.Join("；", diagnostics),
            string.Empty);
    }

    private static async Task<TraceResolution> TryGetCloudflareTraceAsync(
        HttpClient client,
        AddressFamily addressFamily,
        CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://www.cloudflare.com/cdn-cgi/trace");
            request.Headers.UserAgent.ParseAdd("ClaudeDesktopGuardian/2.0");
            using var response = await client.SendAsync(request, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            var values = body.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Split('=', 2))
                .Where(parts => parts.Length == 2)
                .ToDictionary(parts => parts[0].Trim(), parts => parts[1].Trim());
            var ip = values.GetValueOrDefault("ip", string.Empty);
            var country = values.GetValueOrDefault("loc", string.Empty).ToUpperInvariant();
            if (!IPAddress.TryParse(ip, out var parsedIp) ||
                (addressFamily == AddressFamily.InterNetworkV6 &&
                 parsedIp.AddressFamily != AddressFamily.InterNetworkV6) ||
                (addressFamily == AddressFamily.InterNetwork &&
                 parsedIp.AddressFamily != AddressFamily.InterNetwork))
            {
                var familyName = addressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4";
                return new TraceResolution(
                    string.Empty,
                    country,
                    $"{familyName} 连接已建立，但出口服务返回的地址不是 {familyName}",
                    "cloudflare");
            }

            return new TraceResolution(
                ip,
                country,
                addressFamily == AddressFamily.InterNetworkV6
                    ? "已通过 VPN IPv6 路由取得公网 IPv6 出口"
                    : string.Empty,
                "cloudflare");
        }
        catch (Exception exception)
        {
            var familyName = addressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4";
            return new TraceResolution(
                string.Empty,
                string.Empty,
                $"{familyName} 出口探测失败：{exception.GetType().Name} {exception.Message}",
                string.Empty);
        }
    }

    private static async Task<(IReadOnlyList<string> Ips, string Detail)> ProbeClaudeDnsAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            var addresses = (await Dns.GetHostAddressesAsync("claude.ai", cancellationToken))
                .Where(addr => addr.AddressFamily == AddressFamily.InterNetwork)
                .Select(addr => addr.ToString())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (addresses.Length == 0)
            {
                return (Array.Empty<string>(), "claude.ai 未解析到 IPv4 记录");
            }

            var isFakeIp = addresses.All(ip => ip.StartsWith("198.18.", StringComparison.Ordinal));
            var detail = isFakeIp
                ? $"claude.ai 解析到 Fake-IP（{string.Join(", ", addresses)}），已走代理隧道"
                : $"claude.ai 解析为 {string.Join(", ", addresses)}";
            return (addresses, detail);
        }
        catch (Exception ex)
        {
            return (Array.Empty<string>(), $"claude.ai DNS 解析失败：{ex.Message}");
        }
    }

    private static async Task<(string Org, string Type, string Detail)> ProbeAsnAsync(
        string exitIp,
        CancellationToken cancellationToken)
    {
        var org = string.Empty;
        var asnType = string.Empty;

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"https://ipinfo.io/{Uri.EscapeDataString(exitIp)}/json");
            req.Headers.UserAgent.ParseAdd("ClaudeDesktopGuardian/2.0");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(6));
            using var resp = await Http.SendAsync(req, timeout.Token);
            if (resp.IsSuccessStatusCode)
            {
                var body = await resp.Content.ReadAsStringAsync(timeout.Token);
                using var doc = JsonDocument.Parse(body);
                var returnedIp = doc.RootElement.TryGetProperty("ip", out var ipEl) ? ipEl.GetString() : string.Empty;
                if (string.Equals(returnedIp, exitIp, StringComparison.OrdinalIgnoreCase) &&
                    doc.RootElement.TryGetProperty("org", out var orgEl))
                {
                    org = orgEl.GetString()?.Trim() ?? string.Empty;
                }
            }
        }
        catch
        {
        }

        if (string.IsNullOrWhiteSpace(org))
        {
            return (string.Empty, string.Empty, "未获取到 ASN 归属信息");
        }

        var match = Regex.Match(org, @"^AS(\d+)\s", RegexOptions.IgnoreCase);
        if (match.Success)
        {
            var asn = match.Groups[1].Value;
            try
            {
                using var req = new HttpRequestMessage(
                    HttpMethod.Get,
                    $"https://www.peeringdb.com/api/net?asn={asn}&fields=asn,info_type");
                req.Headers.UserAgent.ParseAdd("ClaudeDesktopGuardian/2.0");
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(6));
                using var resp = await Http.SendAsync(req, timeout.Token);
                if (resp.IsSuccessStatusCode)
                {
                    var body = await resp.Content.ReadAsStringAsync(timeout.Token);
                    using var doc = JsonDocument.Parse(body);
                    if (doc.RootElement.TryGetProperty("data", out var dataProp) &&
                        dataProp.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var item in dataProp.EnumerateArray())
                        {
                            var itemAsn = item.TryGetProperty("asn", out var aEl) ? aEl.ToString() : string.Empty;
                            if (string.Equals(itemAsn, asn, StringComparison.Ordinal))
                            {
                                asnType = item.TryGetProperty("info_type", out var tEl)
                                    ? tEl.GetString()?.Trim() ?? string.Empty
                                    : string.Empty;
                                break;
                            }
                        }
                    }
                }
            }
            catch
            {
            }
        }

        var detail = string.Equals(asnType, "Cable/DSL/ISP", StringComparison.OrdinalIgnoreCase)
            ? $"ISP（{org}）；注：ASN 类型不等于具体 IP 住宅认证"
            : !string.IsNullOrWhiteSpace(asnType)
                ? $"{asnType}（{org}）；请核实节点是否为数据中心/机房"
                : $"网络类型未确认（{org}）";

        return (org, asnType, detail);
    }

    private static (string Language, string Source) ReadClaudeClientLanguage()
    {
        var install = ClaudeInstallDiscovery.Discover();
        var candidates = new List<string> { Path.Combine(install.ActiveDataPath, "config.json") };
        if (!string.IsNullOrWhiteSpace(install.MsixDataPath))
        {
            var msixConfig = Path.Combine(install.MsixDataPath, "config.json");
            if (!candidates.Contains(msixConfig, StringComparer.OrdinalIgnoreCase))
            {
                candidates.Add(msixConfig);
            }
        }

        foreach (var path in candidates)
        {
            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                var raw = File.ReadAllText(path);
                using var doc = JsonDocument.Parse(raw);
                if (doc.RootElement.TryGetProperty("locale", out var localeProp) &&
                    localeProp.ValueKind == JsonValueKind.String)
                {
                    var locale = localeProp.GetString()?.Trim() ?? string.Empty;
                    if (Regex.IsMatch(locale, @"^[a-z]{2,3}(?:-[a-z0-9]{2,8})*$", RegexOptions.IgnoreCase))
                    {
                        return (locale, path);
                    }
                }
            }
            catch
            {
            }
        }

        return (string.Empty, string.Empty);
    }

    private static bool HasIpv6Route(NetworkInterface? adapter)
    {
        if (adapter is null || adapter.OperationalStatus != OperationalStatus.Up)
        {
            return false;
        }

        var properties = adapter.GetIPProperties();
        var hasIpv6Address = properties.UnicastAddresses.Any(address =>
            address.Address.AddressFamily == AddressFamily.InterNetworkV6 &&
            !address.Address.IsIPv6LinkLocal &&
            !address.Address.IsIPv6Multicast &&
            !IPAddress.IsLoopback(address.Address));
        var hasIpv6Gateway = properties.GatewayAddresses.Any(address =>
            address.Address.AddressFamily == AddressFamily.InterNetworkV6 &&
            !address.Address.IsIPv6Multicast);
        return hasIpv6Address && hasIpv6Gateway;
    }

    public static IReadOnlyList<string> InspectPublicIpv6Routes(NetworkInterface? vpnAdapter)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Array.Empty<string>();
        }

        var vpnIndex = vpnAdapter is not null ? GetIpv6InterfaceIndex(vpnAdapter) : -1;
        var indexToName = new Dictionary<int, string>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var idx = GetIpv6InterfaceIndex(nic);
            if (idx > 0)
            {
                indexToName[idx] = nic.Name;
            }
        }

        var leakingAdapters = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (GetIpForwardTable2(23 /* AF_INET6 */, out var tablePtr) != 0 || tablePtr == IntPtr.Zero)
        {
            return Array.Empty<string>();
        }

        try
        {
            var numEntries = Marshal.ReadInt32(tablePtr);
            // MIB_IPFORWARD_TABLE2: 4-byte NumEntries + 4-byte padding for 8-byte-aligned MIB_IPFORWARD_ROW2 (104 bytes)
            const int offset = 8;
            const int rowSize = 104;
            var addrBytes = new byte[16];
            for (var i = 0; i < numEntries; i++)
            {
                var rowPtr = IntPtr.Add(tablePtr, offset + i * rowSize);
                var interfaceIndex = Marshal.ReadInt32(rowPtr, 8);
                if (interfaceIndex == vpnIndex)
                {
                    continue; // Routes via the VPN TUN adapter itself are handled by the IPv6 egress probe
                }

                Marshal.Copy(IntPtr.Add(rowPtr, 20), addrBytes, 0, 16);
                var prefixLen = Marshal.ReadByte(rowPtr, 40);
                if (IsPublicOrNat64Ipv6Prefix(addrBytes, prefixLen))
                {
                    var name = indexToName.TryGetValue(interfaceIndex, out var alias)
                        ? alias
                        : $"ifIndex={interfaceIndex}";
                    leakingAdapters.Add(name);
                }
            }
        }
        catch
        {
        }
        finally
        {
            FreeMibTable(tablePtr);
        }

        return leakingAdapters.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public static bool IsPublicOrNat64Ipv6Prefix(byte[] addressBytes, int prefixLength)
    {
        if (addressBytes.Length != 16)
        {
            return false;
        }

        // Default route ::/0 or global unicast 2000::/3
        var bits = Math.Min(Math.Max(prefixLength, 0), 3);
        var mask = bits == 0 ? 0 : (0xFF << (8 - bits)) & 0xFF;
        if ((addressBytes[0] & mask) == (0x20 & mask))
        {
            return true;
        }

        // Well-known NAT64 prefix 64:ff9b::/96 or 64:ff9b:1::/48
        if (addressBytes[0] == 0x00 && addressBytes[1] == 0x64 &&
            addressBytes[2] == 0xFF && addressBytes[3] == 0x9B)
        {
            return true;
        }

        return false;
    }

    private static int GetIpv6InterfaceIndex(NetworkInterface nic)
    {
        try
        {
            return nic.GetIPProperties().GetIPv6Properties()?.Index ?? -1;
        }
        catch
        {
            return -1;
        }
    }

    private static HashSet<int> GetIpv4DefaultRouteInterfaceIndexes()
    {
        var result = new HashSet<int>();
        if (!OperatingSystem.IsWindows())
        {
            return result;
        }

        if (GetIpForwardTable2(2 /* AF_INET */, out var tablePtr) != 0 || tablePtr == IntPtr.Zero)
        {
            return result;
        }

        try
        {
            var numEntries = Marshal.ReadInt32(tablePtr);
            const int offset = 8;
            const int rowSize = 104;
            for (var i = 0; i < numEntries; i++)
            {
                var rowPtr = IntPtr.Add(tablePtr, offset + i * rowSize);
                var prefixLen = Marshal.ReadByte(rowPtr, 40);
                var destIpv4 = Marshal.ReadInt32(rowPtr, 16);
                if (prefixLen == 0 && destIpv4 == 0)
                {
                    result.Add(Marshal.ReadInt32(rowPtr, 8));
                }
            }
        }
        catch
        {
        }
        finally
        {
            FreeMibTable(tablePtr);
        }

        return result;
    }

    private static async Task<IReadOnlyDictionary<string, string>> ProbeClaudeHttpsAsync(
        IReadOnlyList<string> domains,
        CancellationToken cancellationToken)
    {
        var results = await Task.WhenAll(domains.Select(async domain =>
        {
            var status = string.Empty;
            for (var attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    var path = domain.Equals("api.anthropic.com", StringComparison.OrdinalIgnoreCase)
                        ? "/v1/models"
                        : "/";
                    using var request = new HttpRequestMessage(HttpMethod.Get, $"https://{domain}{path}");
                    request.Headers.UserAgent.ParseAdd("ClaudeDesktopGuardian/2.0");
                    using var response = await Http.SendAsync(
                        request,
                        HttpCompletionOption.ResponseHeadersRead,
                        cancellationToken);
                    status = ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture);
                    break;
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    status = "timeout";
                }
                catch (Exception exception)
                {
                    status = exception.GetType().Name;
                }

                if (attempt == 0)
                {
                    await Task.Delay(350, cancellationToken);
                }
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

            var targetAddresses = addresses.Take(4).ToArray();
            var probeResults = await Task.WhenAll(
                targetAddresses.Select(address => ProbeStunAddressAsync(host, port, address, addressFamily, cancellationToken)));
            var okResult = probeResults.FirstOrDefault(r => r.Status == "ok");
            if (okResult is not null)
            {
                return okResult;
            }

            var details = DeduplicateStunDetails(probeResults.Select(r => r.Detail));
            return new StunResult(host, port, "unknown", string.Empty, details);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new StunResult(host, port, "unknown", string.Empty, $"{FormatAddressFamily(addressFamily)} STUN 超时");
        }
        catch (Exception exception)
        {
            return new StunResult(host, port, "unknown", string.Empty, $"{FormatAddressFamily(addressFamily)} {exception.GetType().Name}");
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
            var transaction = new byte[12];
            Random.Shared.NextBytes(transaction);
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
                ? new StunResult(host, port, "unknown", string.Empty, $"{FormatAddressFamily(addressFamily)} 响应未包含有效映射地址")
                : new StunResult(host, port, "ok", mapped, $"{FormatAddressFamily(addressFamily)} 收到 STUN 映射地址");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new StunResult(host, port, "unknown", string.Empty, $"{FormatAddressFamily(addressFamily)} STUN 超时");
        }
        catch (Exception exception)
        {
            return new StunResult(host, port, "unknown", string.Empty, $"{FormatAddressFamily(addressFamily)} {exception.GetType().Name}");
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

            if ((type == 0x0001 || type == 0x0020) && length >= 8 && response[position + 5] == 0x01)
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

            if ((type == 0x0001 || type == 0x0020) && length >= 20 && response[position + 5] == 0x02)
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

    internal static string DeduplicateStunDetails(IEnumerable<string> rawDetails)
    {
        var distinct = rawDetails
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(d => d.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return distinct.Length == 0 ? "STUN 超时" : string.Join("；", distinct);
    }

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
                rows.Add(new TcpRow((TcpState)row.State, row.ProcessId, remoteAddress, remotePort));
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

    [DllImport("iphlpapi.dll")]
    private static extern uint GetIpForwardTable2(ushort family, out IntPtr table);

    [DllImport("iphlpapi.dll")]
    private static extern void FreeMibTable(IntPtr memory);

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

    private sealed record TcpRow(TcpState State, uint ProcessId, string RemoteAddress, ushort RemotePort);

    private static HttpClient CreateHttpClient(AddressFamily addressFamily, bool useSystemProxy)
    {
        var handler = new SocketsHttpHandler { UseProxy = useSystemProxy };

        if (!useSystemProxy && addressFamily == AddressFamily.InterNetworkV6)
        {
            handler.ConnectCallback = async (context, cancellationToken) =>
            {
                var addresses = (await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken))
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
                        using var attemptTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                        attemptTimeout.CancelAfter(TimeSpan.FromSeconds(3));
                        await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), attemptTimeout.Token);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (Exception exception)
                    {
                        lastException = exception;
                        socket.Dispose();
                    }
                }

                throw new HttpRequestException($"无法连接 {context.DnsEndPoint.Host} 的 {addressFamily} 地址", lastException);
            };
        }

        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
    }

    private sealed record TraceResolution(string Ip, string Country, string Detail, string Source = "")
    {
        public static TraceResolution Empty { get; } = new(string.Empty, string.Empty, string.Empty, string.Empty);
    }
}
