using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.AuthorizationCode {
    public class T4_4_1_5_CodePhishing : Threat {

        public override string Id => "6819_4_4_1_5";

        public override string Description => "Authorization 'code' Phishing";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.AuthorizationCodeLeaked];
        public override string[] Countermeasures => [
            "The redirect URI of the client should point to an HTTPS-protected endpoint",
            "The authorization server should require that the client be authenticated, i.e., confidential client"
            ];
    }
}
