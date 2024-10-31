using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_6_AccessTokenInjection : Threat {
        public override string Id => "BCP_4_6";

        public override string Description => "Access Token Injection";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel, ConsequenceTypes.AccessTokenLeaked];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.UsableAccessTokenLeaked];
        public override string[] Countermeasures => [
            "There is no way to detect such an injection attack in pure-OAuth flows, since the token is issued without any binding to the transaction or the particular user agent",
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.Client];
    }
}
