using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_13_TerminatingReverseProxies : Threat {
        public override string Id => "BCP_4_13";

        public override string Description => "TLS Terminating Reverse Proxies";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.UsesReverseProxy];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.PrivilegeEscalation];

        public override string[] Countermeasures => [
            "A reverse proxy MUST therefore sanitize any inbound requests to ensure the authenticity and integrity of all header values relevant for the security of the application servers."
            ];
    }
}
