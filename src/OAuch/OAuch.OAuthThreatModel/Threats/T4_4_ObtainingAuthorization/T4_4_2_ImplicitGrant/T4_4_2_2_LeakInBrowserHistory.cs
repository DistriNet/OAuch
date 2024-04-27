using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.ImplicitGrant {
    public class T4_4_2_2_LeakInBrowserHistory : Threat {
        public override string Id => "6819_4_4_2_2";

        public override string Description => "Access Token Leak in Browser History";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Use short expiry time for tokens",
            "Make responses non-cacheable"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.SystemsAttacker];
    }
}
