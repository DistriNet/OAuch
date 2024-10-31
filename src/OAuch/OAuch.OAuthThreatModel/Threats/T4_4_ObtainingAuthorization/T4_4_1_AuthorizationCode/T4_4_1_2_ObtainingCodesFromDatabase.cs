using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.AuthorizationCode {
    public class T4_4_1_2_ObtainingCodesFromDatabase : Threat {
        public override string Description => "Obtaining Authorization \"codes\" from Authorization Server Database";

        public override string Id => "6819_4_4_1_2";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AuthorizationCodeLeaked];

        public override string[] Countermeasures => [
            "Best practices for credential storage protection should be employed",
            "Enforce system security measures",
            "Store access token hashes only",
            "Enforce standard SQL injection countermeasures"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.SystemsAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.TokenEndpoint];
    }
}
