using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;

namespace OAuch.OAuthThreatModel.Threats.AuthorizationEndpoint {
    /// <summary>
    /// If the client is public, it can be impersonated to get the access token
    /// </summary>
    public class T4_2_3A_AuthorizationByFraud : Threat {
        public override string Description => "Malicious Client Obtains Existing Authorization by Fraud";

        public override string Id => "6819_4_2_3";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.IsPublicClient];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "Authorization servers should not automatically process repeat authorizations to public clients unless the client is validated using a pre-registered redirect URI",
            "Authorization servers can mitigate the risks associated with automatic processing by limiting the scope of access tokens obtained through automated approvals"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.AuthorizationEndpoint];
    }
    /// <summary>
    /// If the client uses the authorization code grant, it can be impersonated to get the authorization code
    /// </summary>
    public class T4_2_3B_AuthorizationByFraud : Threat {
        public override string Description => "Malicious Client Obtains Existing Authorization by Fraud";

        public override string Id => "6819_4_2_3";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AuthorizationCodeLeaked];

        public override string[] Countermeasures => [
            "Authorization servers should not automatically process repeat authorizations to public clients unless the client is validated using a pre-registered redirect URI",
            "Authorization servers can mitigate the risks associated with automatic processing by limiting the scope of access tokens obtained through automated approvals"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
        public override InvolvedParty[] Parties => [InvolvedParty.AuthorizationEndpoint];
    }
}