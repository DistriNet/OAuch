using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_3_1_AuthCodeInBrowserHistory : Threat {
        public override string Id => "BCP_4_3_1";

        public override string Description => "Authorization Code in Browser History";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AuthorizationCodeLeaked];

        public override string[] Countermeasures => [
            "Authorization code replay prevention",
            "Use form post response mode instead of redirect for the authorization response"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.SystemsAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.UserAgent];
    }
    public class BCP_4_3_2_TokenInApiUri : Threat {
        public override string Id => "BCP_4_3_2_A";

        public override string Description => "Access Token in Browser History";

        public override ConsequenceType[] DependsOn => [];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Use the authorization code grant or alternative OAuth response modes like the form post response mode"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.SystemsAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.ResourceServer];
    }
    public class BCP_4_3_2_TokenInBrowserHistory : Threat {
        public override string Id => "BCP_4_3_2_B";

        public override string Description => "Access Token in Browser History";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Use the authorization code grant or alternative OAuth response modes like the form post response mode"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.SystemsAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.UserAgent];
    }
}
