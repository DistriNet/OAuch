using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.TokenEndpoint {
    public class T4_3_5_ObtainingSecretByGuessing : Threat {
        public override string Description => "Obtaining Client Secret by Online Guessing";

        public override string Id => "6819_4_3_5";

        public override ConsequenceType[] DependsOn => [];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.ClientAuthenticationSidestepped];

        public override string[] Countermeasures => [
            "Use high entropy for secrets ",
            "Lock accounts",
            "Use strong client authentication"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.TokenEndpoint];
    }
}
