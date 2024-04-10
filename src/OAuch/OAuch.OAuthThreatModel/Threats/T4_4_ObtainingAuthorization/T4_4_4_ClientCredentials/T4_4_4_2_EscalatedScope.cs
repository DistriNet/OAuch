using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ClientCredentials {
    public class T4_4_4_2_EscalatedScope : Threat {
        public override string Id => "6819_4_4_4_2";

        public override string Description => "Client Obtains Additional Scopes";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.MachineToMachine];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.PrivilegeEscalation];

        public override string[] Countermeasures => [
            "The authorization server may generally restrict the scope of access tokens issued by this flow",
            "The authorization server could notify the resource owner by an appropriate medium of the grant issued"
            ];
    }
}
