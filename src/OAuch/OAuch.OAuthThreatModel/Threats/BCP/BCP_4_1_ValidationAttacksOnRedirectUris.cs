using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.BCP4_1_RedirectUriValidation {
    public class BCP_4_1_1_ValidationAttacksOnAuthorizationGrant : Threat {
        public override string Id => "BCP_4_1_1";
        public override string Description => "Redirect URI Validation Attacks on Authorization Code Grant";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.AuthorizationCodeLeaked];

        public override string[] Countermeasures => [
            "The authorization server MUST ensure that the two URIs are equal",
            "Web servers on which redirect URIs are hosted MUST NOT expose open redirectors",
            "Servers MAY prevent browsers from reattaching fragments to redirection URLs by attaching an arbitrary fragment identifier, for example #_, to URLs in Location headers"
            ];
    }
    public class BCP_4_1_2_ValidationAttacksOnImplicitGrant : Threat {
        public override string Id => "BCP_4_1_2";
        public override string Description => "Redirect URI Validation Attacks on Implicit Grant";

        public override IReadOnlyList<ConsequenceType> DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override IReadOnlyList<ConsequenceType> Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "The authorization server MUST ensure that the two URIs are equal",
            "Web servers on which redirect URIs are hosted MUST NOT expose open redirectors",
            "Servers MAY prevent browsers from reattaching fragments to redirection URLs by attaching an arbitrary fragment identifier, for example #_, to URLs in Location headers",
            "Clients SHOULD use the authorization code response type instead of response types causing access token issuance at the authorization endpoint"
            ];

    }
}
