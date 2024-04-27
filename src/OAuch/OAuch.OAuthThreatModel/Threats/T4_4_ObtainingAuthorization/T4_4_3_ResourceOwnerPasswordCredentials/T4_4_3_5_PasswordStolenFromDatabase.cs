using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ResourceOwnerPasswordCredentials {
    public class T4_4_3_5_PasswordStolenFromDatabase : Threat {
        public override string Id => "6819_4_4_3_5";

        public override string Description => "Obtaining User Passwords from Authorization Server Database";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.ClientHoldsUserPassword];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PasswordLeaked];

        public override string[] Countermeasures => [
            "Enforce credential storage protection best practices"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.SystemsAttacker];
    }
}
