using ClaudeDesktopGuardian.Core;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace ClaudeDesktopGuardian.Helper;

internal sealed record FirewallRuleEvidence(string Name, string Group, string Application, string PackageSid,
    bool Enabled, int Direction, int Action, int Protocol, int Profiles, string LocalPorts, string RemotePorts,
    string LocalAddresses, string RemoteAddresses, string InterfaceTypes, bool InterfaceRestricted,
    string ServiceName, string LocalUsers, string RemoteUsers = "", string RemoteMachines = "", int SecureFlags = 0);

internal sealed record FirewallPolicyEvidence(bool Readable, bool? Effective,
    IReadOnlyList<FirewallRuleEvidence> Rules, string Detail);

internal interface IFirewallPolicyStore
{
    FirewallPolicyEvidence Read(string group);
    void Add(FirewallRuleEvidence rule);
    void Remove(string name);
}

internal sealed partial class WindowsHelperSystemExecutor
{
    private readonly IFirewallPolicyStore _firewall;
    private readonly Func<ClaudeInstallation> _discoverTcpOnly;

    public WindowsHelperSystemExecutor(IFirewallPolicyStore? firewall = null, Func<ClaudeInstallation>? discover = null)
    {
        _firewall = firewall ?? new WindowsFirewallPolicyStore();
        _discoverTcpOnly = discover ?? (() => ClaudeInstallDiscovery.Discover(forceRefresh: true));
    }

    private IReadOnlyList<FirewallRuleEvidence> ExpectedTcpOnlyRules(string group)
    {
        var install = _discoverTcpOnly();
        var targets = install.ExecutablePaths.Where(IsAllowedClaudePath)
            .Distinct(StringComparer.OrdinalIgnoreCase).Select(path => (Path: path, Package: "")).ToList();
        if (!string.IsNullOrWhiteSpace(install.PackageFamilyName))
        {
            Marshal.ThrowExceptionForHR(DeriveAppContainerSidFromAppContainerName(install.PackageFamilyName, out var pointer));
            try { targets.Add(("", new SecurityIdentifier(pointer).Value)); }
            finally { FreeSid(pointer); }
        }
        return targets.Select(target => new FirewallRuleEvidence(
            group + ".Managed.Udp." + HelperCommandDispatcher.HashPath(target.Path + "|" + target.Package), group,
            target.Path, target.Package, true, 2, 0, 17, 7, "*", "*", "*", "*", "All", false, "",
            $"O:LSD:(A;;CC;;;{CurrentUserSid})")).ToArray();
    }

    internal static bool RuleMatches(FirewallRuleEvidence actual, FirewallRuleEvidence expected) =>
        string.Equals(actual.Name, expected.Name, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(actual.Group, expected.Group, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(actual.Application, expected.Application, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(actual.PackageSid, expected.PackageSid, StringComparison.OrdinalIgnoreCase) &&
        actual.Enabled && actual.Direction == 2 && actual.Action == 0 && actual.Protocol == 17 && actual.Profiles == 7 &&
        actual.LocalPorts == "*" && actual.RemotePorts == "*" && actual.LocalAddresses == "*" && actual.RemoteAddresses == "*" &&
        actual.InterfaceTypes.Equals("All", StringComparison.OrdinalIgnoreCase) && !actual.InterfaceRestricted &&
        string.IsNullOrEmpty(actual.ServiceName) &&
        string.Equals(actual.LocalUsers, expected.LocalUsers, StringComparison.OrdinalIgnoreCase) &&
        string.IsNullOrEmpty(actual.RemoteUsers) && string.IsNullOrEmpty(actual.RemoteMachines) && actual.SecureFlags == 0;

    internal static bool IsManagedUdpRule(string name, string group) =>
        name.StartsWith(group + ".Managed.Udp.", StringComparison.OrdinalIgnoreCase) &&
        Regex.IsMatch(name[(group.Length + ".Managed.Udp.".Length)..], "\\A[0-9A-F]{16}\\z", RegexOptions.IgnoreCase);

    public HelperTcpOnlyStatus QueryTcpOnlyStatus(string groupName)
    {
        try
        {
            var policy = _firewall.Read(groupName);
            if (!policy.Readable) return new("unknown", policy.Detail);
            var owned = policy.Rules.Where(rule => IsManagedUdpRule(rule.Name, groupName)).ToArray();
            if (owned.Length == 0) return new("off", "Claude TCP-only 托管规则未启用");
            if (policy.Effective != true) return new(policy.Effective == false ? "invalid" : "unknown", policy.Detail);
            var expected = ExpectedTcpOnlyRules(groupName);
            if (expected.Count == 0 || expected.Count != owned.Length ||
                expected.Any(rule => !owned.Any(actual => RuleMatches(actual, rule))))
                return new("stale", "Claude 安装身份变化、规则缺失或规则属性不符；需要显式刷新", owned.Length);
            return new("active", $"已读回 {owned.Length} 条 Claude 专属出站 UDP 全端口/接口/配置阻断规则；尚未进行抓包验收", owned.Length);
        }
        catch (Exception error) { return new("unknown", "TCP-only 核验失败：" + error.GetType().Name); }
    }

    public Task<HelperTcpOnlyStatus> EnableTcpOnlyAsync(string groupName)
    {
        var expected = ExpectedTcpOnlyRules(groupName);
        if (expected.Count == 0) return Task.FromResult(new HelperTcpOnlyStatus("unknown", "未发现 Claude 安装身份"));
        var policy = _firewall.Read(groupName);
        if (!policy.Readable || policy.Effective != true)
            return Task.FromResult(new HelperTcpOnlyStatus("unknown", policy.Detail));
        foreach (var existing in policy.Rules.Where(rule => IsManagedUdpRule(rule.Name, groupName)))
            _firewall.Remove(existing.Name);
        foreach (var rule in expected) _firewall.Add(rule);
        return Task.FromResult(QueryTcpOnlyStatus(groupName));
    }

    public Task DisableTcpOnlyAsync(string groupName)
    {
        var policy = _firewall.Read(groupName);
        if (!policy.Readable) throw new InvalidOperationException(policy.Detail);
        foreach (var rule in policy.Rules.Where(rule => IsManagedUdpRule(rule.Name, groupName)))
            _firewall.Remove(rule.Name);
        return Task.CompletedTask;
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
    [DllImport("advapi32.dll")]
    private static extern IntPtr FreeSid(IntPtr sid);
}

internal sealed class WindowsFirewallPolicyStore : IFirewallPolicyStore
{
    // 0 = NET_FW_MODIFY_STATE_OK; 2 = NET_FW_MODIFY_STATE_INBOUND_BLOCKED (still enforces outbound block rules);
    // 1 = NET_FW_MODIFY_STATE_GP_OVERRIDE (Group Policy overrides local rules).
    internal static bool IsLocalPolicyStateEffective(int modifyState) => modifyState is 0 or 2;

    public FirewallPolicyEvidence Read(string group)
    {
        object? instance = null;
        try
        {
            instance = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!);
            dynamic policy = instance!;
            var active = (int)policy.CurrentProfileTypes;
            var effective = active != 0 && IsLocalPolicyStateEffective((int)policy.LocalPolicyModifyState) &&
                ServiceRunning("BFE") && ServiceRunning("MpsSvc");
            foreach (var (flag, name) in new[] { (1, "DomainProfile"), (2, "PrivateProfile"), (4, "PublicProfile") })
            {
                if ((active & flag) == 0) continue;
                effective &= (bool)policy.FirewallEnabled[flag];
                object? exclusions = policy.ExcludedInterfaces[flag];
                if (exclusions is Array excluded) effective &= excluded.Length == 0;
                else if (exclusions is not null && exclusions is not DBNull)
                    throw new InvalidOperationException("无法读取排除的防火墙接口");
                using var profile = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\WindowsFirewall\" + name);
                effective &= profile?.GetValue("AllowLocalPolicyMerge") is not int merge || merge != 0;
                effective &= profile?.GetValue("EnableFirewall") is not int enabled || enabled != 0;
            }
            var rules = new List<FirewallRuleEvidence>();
            foreach (dynamic rule in policy.Rules)
            {
                try
                {
                    if (!string.Equals((string)rule.Grouping, group, StringComparison.OrdinalIgnoreCase)) continue;
                    var protocol = (int)rule.Protocol;
                    rules.Add(new((string)rule.Name, (string)rule.Grouping, (string?)rule.ApplicationName ?? "",
                        (string?)rule.LocalAppPackageId ?? "", (bool)rule.Enabled, (int)rule.Direction, (int)rule.Action,
                        protocol, (int)rule.Profiles, protocol is 6 or 17 ? (string?)rule.LocalPorts ?? "" : "",
                        protocol is 6 or 17 ? (string?)rule.RemotePorts ?? "" : "", (string?)rule.LocalAddresses ?? "",
                        (string?)rule.RemoteAddresses ?? "", (string?)rule.InterfaceTypes ?? "", rule.Interfaces is Array interfaces && interfaces.Length > 0,
                        (string?)rule.serviceName ?? "", (string?)rule.LocalUserAuthorizedList ?? "",
                        (string?)rule.RemoteUserAuthorizedList ?? "", (string?)rule.RemoteMachineAuthorizedList ?? "", (int)rule.SecureFlags));
                }
                finally { Marshal.FinalReleaseComObject(rule); }
            }
            return new(true, effective, rules, effective ? "BFE/MpsSvc 与活动防火墙配置启用，本地规则允许生效"
                : "防火墙服务/活动配置关闭，或本地规则受到系统策略覆盖");
        }
        catch (Exception error) { return new(false, null, Array.Empty<FirewallRuleEvidence>(), "防火墙有效策略读取失败：" + error.GetType().Name); }
        finally { if (instance is not null) Marshal.FinalReleaseComObject(instance); }
    }

    public void Add(FirewallRuleEvidence value)
    {
        object? instance = null;
        object? ruleObject = null;
        try
        {
            instance = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)!);
            ruleObject = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true)!);
            dynamic policy = instance!;
            dynamic rule = ruleObject!;
            rule.Name = value.Name;
            rule.Grouping = value.Group;
            rule.Description = "ClaudeDesktopGuardian managed outbound UDP policy";
            rule.Protocol = value.Protocol;
            if (value.Application.Length > 0) rule.ApplicationName = value.Application;
            if (value.PackageSid.Length > 0) rule.LocalAppPackageId = value.PackageSid;
            rule.LocalUserAuthorizedList = value.LocalUsers;
            rule.Direction = value.Direction;
            rule.Action = value.Action;
            rule.Profiles = value.Profiles;
            rule.LocalPorts = value.LocalPorts;
            rule.RemotePorts = value.RemotePorts;
            rule.LocalAddresses = value.LocalAddresses;
            rule.RemoteAddresses = value.RemoteAddresses;
            rule.InterfaceTypes = value.InterfaceTypes;
            rule.Enabled = value.Enabled;
            policy.Rules.Add(rule);
        }
        finally
        {
            if (ruleObject is not null) Marshal.FinalReleaseComObject(ruleObject);
            if (instance is not null) Marshal.FinalReleaseComObject(instance);
        }
    }

    public void Remove(string name)
    {
        dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)!)!;
        try { policy.Rules.Remove(name); }
        finally { Marshal.FinalReleaseComObject(policy); }
    }

    private static bool ServiceRunning(string name)
    {
        var manager = OpenSCManager(null, null, 1);
        if (manager == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        try
        {
            var service = OpenService(manager, name, 4);
            if (service == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
            try
            {
                var status = new byte[36];
                if (!QueryServiceStatusEx(service, 0, status, status.Length, out _))
                    throw new System.ComponentModel.Win32Exception();
                return BitConverter.ToInt32(status, 4) == 4;
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int level, byte[] buffer, int size, out int needed);
    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr service);
}
