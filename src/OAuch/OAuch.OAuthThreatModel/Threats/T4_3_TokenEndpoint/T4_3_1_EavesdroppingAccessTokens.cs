using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.TokenEndpoint {
    public class T4_3_1_EavesdroppingAccessTokens : Threat {
        public override string Description => "Eavesdropping Access Tokens";

        public override string Id => "6819_4_3_1";

        public override ConsequenceType[] DependsOn => [];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "The authorization servers must ensure that transmissions are protected using transport-layer mechanisms such as TLS",
            "If end-to-end confidentiality cannot be guaranteed, reducing scope and expiry time for access tokens can be used to reduce the damage in case of leaks."
            ];
        public override AttackerType[] Attackers => [AttackerTypes.NetworkAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.TokenEndpoint];
    }
}
