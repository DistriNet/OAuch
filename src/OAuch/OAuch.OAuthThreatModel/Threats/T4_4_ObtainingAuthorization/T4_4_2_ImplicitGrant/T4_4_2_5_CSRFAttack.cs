using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ImplicitGrant {
    public class T4_4_2_5_CSRFAttack : Threat {
        public override string Id => "6819_4_4_2_5";

        public override string Description => "CSRF Attack against redirect-uri";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.PrivilegeEscalation];
        public override string[] Countermeasures => [
            "The \"state\" parameter should be used to link the authorization request with the redirect URI used to deliver the access token",
            "Client developers and end users can be educated to not follow untrusted URLs"
            ];
    }
}
