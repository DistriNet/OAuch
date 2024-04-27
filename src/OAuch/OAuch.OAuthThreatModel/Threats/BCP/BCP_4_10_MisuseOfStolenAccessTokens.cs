using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_10_MisuseOfStolenAccessTokens : Threat {
        public override string Id => "BCP_4_10";

        public override string Description => "Misuse of Stolen Access Tokens";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.AccessTokenLeaked];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.UsableAccessTokenLeaked];

        public override string[] Countermeasures => [
            "Sender-Constrained Access Tokens",
            "Audience-Restricted Access Tokens"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker, AttackerTypes.SystemsAttacker, AttackerTypes.NetworkAttacker];
    }
}
