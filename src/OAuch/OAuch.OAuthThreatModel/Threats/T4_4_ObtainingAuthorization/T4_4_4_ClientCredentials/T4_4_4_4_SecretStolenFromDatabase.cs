using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ClientCredentials {
    public class T4_4_4_4_SecretStolenFromDatabase : Threat {
        public override string Id => "6819_4_4_4_4";

        public override string Description => "Obtaining Client Secrets from Authorization Server Database";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.MachineToMachine];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.ClientAuthenticationSidestepped];

        public override string[] Countermeasures => [
            "Enforce credential storage protection best practices"
            ];
    }
}
