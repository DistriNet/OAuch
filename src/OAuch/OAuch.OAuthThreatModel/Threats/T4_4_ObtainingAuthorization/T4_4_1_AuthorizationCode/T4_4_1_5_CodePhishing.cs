using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.AuthorizationCode {
    public class T4_4_1_5_CodePhishing : Threat {

        public override string Id => "6819_4_4_1_5";

        public override string Description => "Authorization 'code' Phishing";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AuthorizationCodeLeaked];
        public override string[] Countermeasures => [
            "The redirect URI of the client should point to an HTTPS-protected endpoint",
            "The authorization server should require that the client be authenticated, i.e., confidential client"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.NetworkAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.Client, InvolvedParty.TokenEndpoint];
    }
}
