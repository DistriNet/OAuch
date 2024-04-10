using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ResourceOwnerPasswordCredentials {
    public class T4_4_3_6_OnlineGuessing : Threat {
        public override string Id => "6819_4_4_3_6";

        public override string Description => "Online Guessing";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.ClientHoldsUserPassword];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.PasswordLeaked];

        public override string[] Countermeasures => [
            "Utilize secure password policy",
            "Lock accounts",
            "Use tar pit",
            "Use CAPTCHAs",
            "Consider not using the grant type \"password\"",
            "Client authentication will provide another authentication factor and thus hinder the attack."
            ];
    }
}
