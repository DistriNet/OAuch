using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Enrichers {
    public class M2MAuthentication : Enricher {
        public override string Id => "M2MAuthentication";

        public override string Description => "When using the client credentials grant, if the client authentication can be sidestepped somehow, the attacker gains full access to the resources";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.MachineToMachine, ConsequenceTypes.ClientAuthenticationSidestepped];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.UsableAccessTokenLeaked];
    }
}
