using NetFwTypeLib;
using System;
using System.Collections;
using System.Net;

namespace CommandLineHelper
{
    /// <summary>
    /// add reference to %system32%\FirewallAPI.dll to import NetFwTypeLib namespace
    /// </summary>
    class FireWallHelper
    {
        const string guidFWPolicy2 = "{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}";
        const string guidRWRule = "{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}";
        static Type typeFWPolicy2;
        static Type typeFWRule;
        static INetFwPolicy2 fwPolicy2;
        static FireWallHelper()
        {
            typeFWPolicy2 = Type.GetTypeFromCLSID(new Guid(guidFWPolicy2));
            typeFWRule = Type.GetTypeFromCLSID(new Guid(guidRWRule));
            fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(typeFWPolicy2);

        }
        public static bool IsPortOpen(int port)
        {
            EnsureSetup();

            Type progID = Type.GetTypeFromProgID("HNetCfg.FwMgr");
            INetFwMgr firewall = Activator.CreateInstance(progID) as INetFwMgr;
            INetFwOpenPorts ports = firewall.LocalPolicy.CurrentProfile.GloballyOpenPorts;
            IEnumerator portEnumerate = ports.GetEnumerator();
            while ((portEnumerate.MoveNext()))
            {
                INetFwOpenPort currentPort = portEnumerate.Current as INetFwOpenPort;
                if (currentPort.Port == port)
                    return true;
            }
            return false;
        }
        static INetFwRule MakeRule(IPAddress remoteIP, string ruleName = null)
        {
            INetFwRule rule = (INetFwRule)Activator.CreateInstance(typeFWRule);
            rule.Name = ruleName ?? $"Inbound block IP {remoteIP}";
            rule.Description = $"Block inbound traffic from {remoteIP} over TCP";
            rule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY;
            rule.RemoteAddresses = remoteIP.ToString();
            rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
            rule.Enabled = true;
            rule.Grouping = "@firewallapi.dll,-23255";
            rule.Profiles = fwPolicy2.CurrentProfileTypes;
            return rule;
        }
        static INetFwRule MakeRule(ushort port, IPAddress remoteIP, string ruleName = null)
        {
            INetFwRule rule = (INetFwRule)Activator.CreateInstance(typeFWRule);
            rule.Name = ruleName ?? $"Inbound block IP {remoteIP}";
            rule.Description = $"Block inbound traffic from {remoteIP} over TCP port {port}";
            rule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY;
            rule.LocalPorts = port.ToString();
            rule.RemoteAddresses = remoteIP.ToString();
            rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
            rule.Enabled = true;
            rule.Grouping = "@firewallapi.dll,-23255";
            rule.Profiles = fwPolicy2.CurrentProfileTypes;
            return rule;
        }

        public static void OpenPort(ushort port, IPAddress remoteIP, string ruleName = null)
        {
            EnsureSetup();
            var newRule = MakeRule(port, remoteIP, ruleName);
            newRule.Enabled = false;
            newRule.Action = NET_FW_ACTION_.NET_FW_ACTION_ALLOW;
            fwPolicy2.Rules.Add(newRule);
        }
        public static void ClosePort(ushort port, IPAddress remoteIP, string ruleName)
        {
            EnsureSetup();
            var newRule = MakeRule(port, remoteIP, ruleName);

            newRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
            fwPolicy2.Rules.Add(newRule);

        }

        public static void CloseIP(IPAddress remoteIP, string ruleName=null)
        {
            EnsureSetup();
            var newRule = MakeRule(remoteIP, ruleName);

            newRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
            fwPolicy2.Rules.Add(newRule);
        }

        public static void OpenIP(IPAddress remoteIP, string ruleName=null)
        {
            EnsureSetup();

            var newRule = MakeRule(remoteIP, ruleName);

            newRule.Action = NET_FW_ACTION_.NET_FW_ACTION_ALLOW;
            fwPolicy2.Rules.Add(newRule);
        }

        public static void OpenPort(ushort port, string applicationName)
        {
            EnsureSetup();

            if (IsPortOpen(port))
                return;

            INetFwOpenPort openPort = GetInstance("INetOpenPort") as INetFwOpenPort;
            openPort.Port = port;
            openPort.Protocol = NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP;
            openPort.Name = applicationName;

            INetFwOpenPorts openPorts = sm_fwProfile.GloballyOpenPorts;
            openPorts.Add(openPort);
        }

        public static void ClosePort(ushort port)
        {
            EnsureSetup();

            if (!IsPortOpen(port))
                return;

            INetFwOpenPorts ports = sm_fwProfile.GloballyOpenPorts;
            ports.Remove(port, NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP);
        }

        private static object GetInstance(string typeName)
        {
            Type tpResult = null;
            switch (typeName)
            {
                case "INetFwMgr":
                    tpResult = Type.GetTypeFromCLSID(new Guid("{304CE942-6E39-40D8-943A-B913C40C9CD4}"));
                    return Activator.CreateInstance(tpResult);
                case "INetAuthApp":
                    tpResult = Type.GetTypeFromCLSID(new Guid("{EC9846B3-2762-4A6B-A214-6ACB603462D2}"));
                    return Activator.CreateInstance(tpResult);
                case "INetOpenPort":
                    tpResult = Type.GetTypeFromCLSID(new Guid("{0CA545C6-37AD-4A6C-BF92-9F7610067EF5}"));
                    return Activator.CreateInstance(tpResult);
                default:
                    throw new Exception("Unknown type name: " + typeName);
            }
        }

        private static void EnsureSetup()
        {
            if (sm_fwProfile != null)
                return;

            INetFwMgr fwMgr = GetInstance("INetFwMgr") as INetFwMgr;
            sm_fwProfile = fwMgr.LocalPolicy.CurrentProfile;
        }

        private static INetFwProfile sm_fwProfile = null;

    }
}
