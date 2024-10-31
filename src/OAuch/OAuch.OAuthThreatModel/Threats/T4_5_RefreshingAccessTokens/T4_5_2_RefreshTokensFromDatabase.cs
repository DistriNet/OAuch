using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.RefreshingAccessTokens {
    public class T4_5_2_RefreshTokensFromDatabase : Threat {
        public override string Id => "6819_4_5_2";

        public override string Description => "Obtaining Refresh Token from Authorization Server Database";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasRefreshToken];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.RefreshTokenLeaked];

        public override string[] Countermeasures => [
            "Enforce credential storage protection best practices",
            "Bind token to client id, if the attacker cannot obtain the required id and secret",
            ];
        public override AttackerType[] Attackers => [AttackerTypes.SystemsAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.TokenEndpoint];
    }
}
