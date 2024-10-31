using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ImplicitGrant {
    public class T4_4_2_3_MaliciousClient : Threat {
        public override string Id => "6819_4_4_2_3";

        public override string Description => "Malicious Client Obtains Authorization";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.UsableAccessTokenLeaked];

        public override string[] Countermeasures => [
            "The authorization server should authenticate the client, if possible",
            "The authorization server should validate the client's redirect URI against the pre-registered redirect URI, if one exists",
            "After authenticating the end user, the authorization server should ask him/her for consent.",
            "The authorization server should not perform automatic re-authorizations for clients it is unable to reliably authenticate or validate",
            "If the authorization server automatically authenticates the end user, it may nevertheless require some user input in order to prevent screen scraping.",
            "The authorization server may also limit the scope of tokens it issues to clients it cannot reliably authenticate"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.SystemsAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.AuthorizationEndpoint];
    }
}
