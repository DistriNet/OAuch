using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_4_MixUpAttacks : Threat {
        public override string Id => "BCP_4_4";

        public override string Description => "Mix-Up Attacks";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.ClientUsesMultipleAuthServers];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.AuthorizationCodeLeaked, ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Mix-Up Defense via Issuer Identification",
            "Mix-Up Defense via Distinct Redirect URIs"
            ];
    }
}
