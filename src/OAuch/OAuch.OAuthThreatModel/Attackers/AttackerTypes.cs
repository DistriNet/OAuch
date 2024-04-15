using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Attackers {
    public static class AttackerTypes {
        static AttackerTypes() {
            WebAttacker = new AttackerType("Web Attacker", "Web Attackers that can set up and operate an arbitrary number of network endpoints (besides the 'honest' ones) including browsers and servers. Web attackers may set up web sites that are visited by the resource owner, operate their own user agents, and participate in the protocol.");
            NetworkAttacker = new AttackerType("Network Attacker", "Network Attackers that additionally have full control over the network over which protocol participants communicate. They can eavesdrop on, manipulate, and spoof messages, except when these are properly protected by cryptographic methods (e.g., TLS). Network attackers can also block arbitrary messages.");
            SystemsAttacker = new AttackerType("Systems Attacker", "Systems Attackers directly attack underlying OAuth infrastructure. They can break into servers with means that are outside of the scope of the OAuth protocol (e.g., an SQL injection to read secrets directly from the authorization server's database).");
        }
        public static IEnumerable<AttackerType> All {
            get {
                var type = typeof(AttackerTypes);
                var props = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
                var ct = typeof(AttackerType);
                return props.Where(p => p.PropertyType == ct).Select(p => (AttackerType)p.GetValue(null)!);
            }
        }
        public static AttackerType WebAttacker { get; }
        public static AttackerType NetworkAttacker { get; }
        public static AttackerType SystemsAttacker { get; }
    }
}
