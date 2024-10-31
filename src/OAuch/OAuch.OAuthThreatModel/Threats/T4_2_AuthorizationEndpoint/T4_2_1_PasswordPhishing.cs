using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.AuthorizationEndpoint {
    public class T4_2_1_PasswordPhishing : Threat {
        public override string Description => "Password Phishing by Counterfeit Authorization Server";

        public override string Id => "6819_4_2_1";

        public override ConsequenceType[] DependsOn => [];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PasswordLeaked];
        public override string[] Countermeasures => [
            "Authorization servers should require the use of transport-layer security for any requests where the authenticity of the authorization server or of request responses is an issue",
            "Authorization servers should educate users about the risks posed by phishing attacks and should provide mechanisms that make it easy for users to confirm the authenticity of their sites."
            ];
        public override AttackerType[] Attackers => [AttackerTypes.NetworkAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.AuthorizationEndpoint];
    }
}
