using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.ObtainingAuthorization.AuthorizationCode {
    public class T_4_4_1_10_ResourceOwnerImpersonation : Threat {
        public override string Id => "6819_4_4_1_10";

        public override string Description => "Resource Owner Impersonation";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.PrivilegeEscalation];
        public override string[] Countermeasures => [
            "Combine password authentication and user consent in a single form",
            "Make use of CAPTCHAs",
            "Use one-time secrets sent out of band to the resource owner",
            ];
        public override AttackerType[] Attackers => [AttackerTypes.SystemsAttacker];
    }
}
