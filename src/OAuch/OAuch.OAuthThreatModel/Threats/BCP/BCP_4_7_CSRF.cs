using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_7_CSRF : Threat {
        public override string Id => "BCP_4_7";

        public override string Description => "Cross Site Request Forgery";

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
