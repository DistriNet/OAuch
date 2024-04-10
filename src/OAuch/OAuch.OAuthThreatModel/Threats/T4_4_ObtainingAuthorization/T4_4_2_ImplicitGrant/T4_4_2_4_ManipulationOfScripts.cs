using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ImplicitGrant {
    public class T4_4_2_4_ManipulationOfScripts : Threat {
        public override string Id => "6819_4_4_2_4";

        public override string Description => "Manipulation of Scripts";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.UsableAccessTokenLeaked, ConsequenceTypes.PrivilegeEscalation];

        public override string[] Countermeasures => [
            "The authorization server should authenticate the server from which scripts are obtained",
            "The client should ensure that scripts obtained have not been altered in transport",
            "Introduce one-time, per-use secrets (e.g., \"client_secret\") values that can only be used by scripts in a small time window once loaded from a server"
            ];
    }
}
