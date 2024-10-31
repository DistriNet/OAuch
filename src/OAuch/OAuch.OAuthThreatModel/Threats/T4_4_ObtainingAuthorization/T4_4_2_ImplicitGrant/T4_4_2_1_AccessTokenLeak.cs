using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ImplicitGrant {
    public class T4_4_2_1_AccessTokenLeak : Threat {
        public override string Id => "6819_4_4_2_1";

        public override string Description => "Access Token Leak in Transport/Endpoints";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "The authorization server should ensure confidentiality (e.g., using TLS) of the response to the client"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.NetworkAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.AuthorizationEndpoint];
    }
}
