using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_8_PKCEDowngrade : Threat {
        public override string Id => "BCP_4_8";

        public override string Description => "PKCE Downgrade Attack";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.SessionAuthenticationSidestepped];

        public override string[] Countermeasures => [
            "Authorization servers MUST mitigate this attack by implementing PKCE correctly",
            "The authorization server MUST ensure that if there was no code_challenge in the authorization request, a request to the token endpoint containing a code_verifier is rejected",
            "Authorization servers that mandate the use of PKCE in general or for particular clients implicitly implement this security measure"
            ];
    }
}
