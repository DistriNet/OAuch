using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.AuthorizationCode {
    public class T4_4_1_8_CSRFAttack : Threat {

        public override string Id => "6819_4_4_1_8";

        public override string Description => "CSRF Attack against redirect-uri";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PrivilegeEscalation];
        public override string[] Countermeasures => [
            "The \"state\" parameter should be used to link the authorization request with the redirect URI used to deliver the access token",
            "Client developers and end users can be educated to not follow untrusted URLs.",
            "Use of PKCE is recommended",
            "The OpenID Connect 'nonce' parameter can also be used"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
    }
}
