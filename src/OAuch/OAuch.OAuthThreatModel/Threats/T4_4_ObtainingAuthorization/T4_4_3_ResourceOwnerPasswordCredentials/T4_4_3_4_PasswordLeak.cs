using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ResourceOwnerPasswordCredentials {
    public class T4_4_3_4_PasswordLeak : Threat {
        public override string Id => "6819_4_4_3_4";

        public override string Description => "Obtaining User Passwords on Transport";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.ClientHoldsUserPassword];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PasswordLeaked];

        public override string[] Countermeasures => [
            "Ensure confidentiality of requests",
            "Use alternative authentication means that do not require the sending of plaintext credentials over the wire"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.NetworkAttacker];
    }
}
