using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ClientCredentials {
    public class T4_4_4_3_SecretLeak : Threat {
        public override string Id => "6819_4_4_4_3";

        public override string Description => "Obtaining Client Secret on Transport";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.MachineToMachine];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.ClientAuthenticationSidestepped];

        public override string[] Countermeasures => [
            "Ensure confidentiality of requests",
            "Use alternative authentication means that do not require the sending of plaintext credentials over the wire"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.NetworkAttacker];
    }
}
