using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.AuthorizationCode {
    public class T4_4_1_11_DoSAttacks : Threat {
        public override string Id => "6819_4_4_1_11";

        public override string Description => "DoS Attacks That Exhaust Resources";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PrivilegeEscalation, ConsequenceTypes.DenialOfService];

        public override string[] Countermeasures => [
            "The authorization server should consider limiting the number of access tokens granted per user",
            "The authorization server should include a nontrivial amount of entropy in authorization \"codes\""
            ];
    }
}
