using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ResourceOwnerPasswordCredentials {
    public class T4_4_3_1_ExposureOfPasswords : Threat {
        public override string Id => "6819_4_4_3_1";

        public override string Description => "Accidental Exposure of Passwords at Client Site";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.ClientHoldsUserPassword];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PasswordLeaked];
        public override string[] Countermeasures => [
            "Use other flows that do not rely on the client's cooperation for secure resource owner credential handling",
            "Use digest authentication instead of plaintext credential processing"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.SystemsAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.Client];
    }
}
