using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.AuthorizationEndpoint {
    public class T4_2_2_TooMuchScope : Threat {
        public override string Description => "User Unintentionally Grants Too Much Access Scope";

        public override string Id => "6819_4_2_2";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.UsesAuthorizationServer];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PrivilegeEscalation];

        public override string[] Countermeasures => [
            "Explain the scope (resources and the permissions) the user is about to grant in an understandable way",
            "Narrow the scope, based on the client."
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.AuthorizationEndpoint];
    }
}
