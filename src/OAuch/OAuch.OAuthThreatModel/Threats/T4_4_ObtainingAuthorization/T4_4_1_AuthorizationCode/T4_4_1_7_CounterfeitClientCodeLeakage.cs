using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.AuthorizationCode {
    public class T4_4_1_7_CounterfeitClientCodeLeakage : Threat {

        public override string Id => "6819_4_4_1_7";

        public override string Description => "Authorization 'code' Leakage through Counterfeit Client";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.AuthorizationCodeLeaked];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PrivilegeEscalation];
        public override string[] Countermeasures => [
            "The authorization server must associate the authorization \"code\" with the redirect URI",
            "The authorization server may also enforce the usage and validation of pre-registered redirect URIs",
            "For native applications, one could also consider using deployment-specific client ids and secrets"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.TokenEndpoint];
    }
}
