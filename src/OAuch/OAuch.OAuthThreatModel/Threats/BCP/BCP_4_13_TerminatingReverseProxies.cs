using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_13_TerminatingReverseProxies : Threat {
        public override string Id => "BCP_4_13";

        public override string Description => "TLS Terminating Reverse Proxies";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.UsesReverseProxy];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PrivilegeEscalation];

        public override string[] Countermeasures => [
            "A reverse proxy MUST therefore sanitize any inbound requests to ensure the authenticity and integrity of all header values relevant for the security of the application servers."
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [];
    }
}
