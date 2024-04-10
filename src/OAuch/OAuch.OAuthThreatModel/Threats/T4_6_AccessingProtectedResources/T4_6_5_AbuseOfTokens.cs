using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.AccessingProtectedResources {
    public class T4_6_5_AbuseOfTokens : Threat {
        public override string Id => "6819_4_6_5";

        public override string Description => "Abuse of Token by Legitimate Resource Server or Client";

        public override IReadOnlyList<ConsequenceType> DependsOn => [];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.PrivilegeEscalation];

        public override string[] Countermeasures => [
            "Tokens should be restricted to particular resource servers"
            ];
    }
}
