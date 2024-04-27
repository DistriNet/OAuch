using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ResourceOwnerPasswordCredentials {
    public class T4_4_3_6_OnlineGuessing : Threat {
        public override string Id => "6819_4_4_3_6";

        public override string Description => "Online Guessing";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.ClientHoldsUserPassword];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PasswordLeaked];

        public override string[] Countermeasures => [
            "Utilize secure password policy",
            "Lock accounts",
            "Use tar pit",
            "Use CAPTCHAs",
            "Consider not using the grant type \"password\"",
            "Client authentication will provide another authentication factor and thus hinder the attack."
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
    }
}
