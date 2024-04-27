using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace OAuch.Compliance.Tests.Concurrency {
    public class MultiResolver {
        public static IReadOnlyList<ServerInfo> Resolve(string url, int howMany = 0 /* <= 0 means everything */) {
            var ips = ResolveAll(url);
            if (ips.Count == 0 || howMany <= 0)
                return ips;

            if (ips.Count >= howMany)
                return ips.Take(howMany).ToList(); // we have too many IPs; trim the list.

            return ips;

            //// we have too few IPs; add duplicates until we reach the required goal
            //var results = new List<ServerInfo>();
            //while(results.Count < howMany) {
            //    int howManyLeft = howMany - results.Count;
            //    results.AddRange(ips.Take(Math.Min(howManyLeft, ips.Count)));
            //}
            //return results;
        }
        public static IReadOnlyList<ServerInfo> ResolveAll(string url) {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                return [];

            // check if we resolved it before
            var host = uri.Host.ToLower();
            if (_serverIps.TryGetValue(host, out var results)) {
                return results;
            }

            // query DNS
            var entry = Dns.GetHostEntry(host);
            var ips = new List<IPAddress>();
            foreach (var ip in entry.AddressList) {
                ips.Add(ip);
            }


            // 'ping' all servers (by connecting to port 443)
            List<ServerInfo> serverInfo = [];
            foreach (var ip in ips) {
                var si = new ServerInfo(ip) {
                    TripTime = ConnectionPing.Ping(ip, 443)
                };
                serverInfo.Add(si);
            }

            _serverIps[host] = serverInfo;
            return serverInfo;

        }
        private static readonly Dictionary<string, IReadOnlyList<ServerInfo>> _serverIps = [];
    }
    public class ServerInfo {
        public ServerInfo(IPAddress ip) {
            this.Ip = ip;
        }
        public IPAddress Ip { get; set; }
        public int TripTime { get; set; }
    }
}
