using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.AccessingProtectedResources {
    public class T4_6_2_ReplayAttacks : Threat {
        public override string Id => "6819_4_6_2";

        public override string Description => "Replay of Authorized Resource Server Requests";

        public override IReadOnlyList<ConsequenceType> DependsOn => [];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.PrivilegeEscalation];

        public override string[] Countermeasures => [
            "The resource server should utilize transport security measures (e.g., TLS) in order to prevent such attacks",
            "The resource server could employ signed requests along with nonces and timestamps in order to uniquely identify requests"
            ];
    }
}
