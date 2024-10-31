using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.T4_4_ObtainingAuthorization.T4_4_2_ImplicitGrant {
    public class T4_4_2_6_TokenSubstitution : Threat {
        public override string Id => "6819_4_4_2_6";

        public override string Description => "Token Substitution (OAuth Login)";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PrivilegeEscalation];

        public override string[] Countermeasures => [
            "Clients should use an appropriate protocol, such as OpenID or SAML to implement user login"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.Client];

    }
}
