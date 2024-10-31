using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_4_MixUpAttacks : Threat {
        public override string Id => "BCP_4_4";

        public override string Description => "Mix-Up Attacks";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.ClientUsesMultipleAuthServers];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AuthorizationCodeLeaked, ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Mix-Up Defense via Issuer Identification",
            "Mix-Up Defense via Distinct Redirect URIs"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.Client];
    }
}
