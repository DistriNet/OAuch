using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_5_AuthorizationCodeInjectionPublic : Threat {
        public override string Id => "BCP_4_5";

        public override string Description => "Authorization Code Injection";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.AuthorizationCodeLeaked];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "The PKCE mechanism specified in RFC7636 can be used as a countermeasure.",
            "OpenID Connect's existing nonce parameter can protect against authorization code injection attacks"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
    }
    public class BCP_4_5_AuthorizationCodeInjectionConfidential : Threat {
        public override string Id => "BCP_4_5";

        public override string Description => "Authorization Code Injection";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.AuthorizationCodeLeaked];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PrivilegeEscalation]; // no access token leak, because it's still the benign client that processes the access token

        public override string[] Countermeasures => [
            "The PKCE mechanism specified in RFC7636 can be used as a countermeasure.",
            "OpenID Connect's existing nonce parameter can protect against authorization code injection attacks"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
    }
}
