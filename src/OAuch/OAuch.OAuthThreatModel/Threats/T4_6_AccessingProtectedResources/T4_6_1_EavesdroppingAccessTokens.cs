using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.AccessingProtectedResources {
    public class T4_6_1_EavesdroppingAccessTokens : Threat {
        public override string Id => "6819_4_6_1";

        public override string Description => "Eavesdropping Access Tokens on Transport";

        public override ConsequenceType[] DependsOn => [];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Access tokens sent as bearer tokens should not be sent in the clear over an insecure channel.",
            "A short lifetime reduces impact in case tokens are compromised",
            "The access token can be bound to a client's identifier and require the client to prove legitimate ownership of the token to the resource server"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.NetworkAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.ResourceServer];
    }
}
