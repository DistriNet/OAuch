using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_15_ResourceOwnerImpersonation : Threat {
        public override string Id => "BCP_4_15";

        public override string Description => "Client Impersonating Resource Owner";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.ClientCanChooseId];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.PrivilegeEscalation];

        public override string[] Countermeasures => [
            "The authorization server SHOULD NOT allow clients to influence their client_id or any claim that could cause confusion with a genuine resource owner",
            ];
    }
}
