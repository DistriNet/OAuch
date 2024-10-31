using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ClientCredentials {
    public class T4_4_4_5_OnlineGuessing : Threat {
        public override string Id => "6819_4_4_4_5";

        public override string Description => "Online Guessing";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.MachineToMachine];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.ClientAuthenticationSidestepped];

        public override string[] Countermeasures => [
            "Utilize secure client secret policy",
            "Lock accounts",
            "Use tar pit"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.TokenEndpoint];
    }
}
