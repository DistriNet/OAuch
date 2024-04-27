using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_8_PKCEDowngrade : Threat {
        public override string Id => "BCP_4_8";

        public override string Description => "PKCE Downgrade Attack";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.SessionAuthenticationSidestepped];

        public override string[] Countermeasures => [
            "Authorization servers MUST mitigate this attack by implementing PKCE correctly",
            "The authorization server MUST ensure that if there was no code_challenge in the authorization request, a request to the token endpoint containing a code_verifier is rejected",
            "Authorization servers that mandate the use of PKCE in general or for particular clients implicitly implement this security measure"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
    }
}
