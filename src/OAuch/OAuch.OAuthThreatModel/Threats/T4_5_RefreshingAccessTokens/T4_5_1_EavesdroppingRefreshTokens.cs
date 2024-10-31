using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.RefreshingAccessTokens {
    public class T4_5_1_EavesdroppingRefreshTokens : Threat {

        public override string Id => "6819_4_5_1";

        public override string Description => "Eavesdropping Refresh Tokens from Authorization Server";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasRefreshToken];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.RefreshTokenLeaked];

        public override string[] Countermeasures => [
            "The authorization servers must ensure that these transmissions are protected using transport-layer mechanisms such as TLS",
            "If end-to-end confidentiality cannot be guaranteed, reducing scope and expiry time for issued access tokens can be used to reduce the damage in case of leaks"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.NetworkAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.TokenEndpoint];
    }
}
