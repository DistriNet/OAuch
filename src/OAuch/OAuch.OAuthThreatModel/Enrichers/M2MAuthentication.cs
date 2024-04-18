using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Enrichers {
    public class M2MAuthentication : Enricher {
        public override string Id => "M2MAuthentication";

        public override string Description => "When using the client credentials grant, if the client does not use authentication, the attacker gains full access to the resources.";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.MachineToMachine, ConsequenceTypes.IsPublicClient];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.UsableAccessTokenLeaked];
    }
}
