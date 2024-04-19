using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Consequences;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Threats.BCP {
    public class BCP_4_2_1_CredentialLeakageFromClientViaRefererAC : Threat {
        public override string Id => "BCP_4_2_1";

        public override string Description => "Credential Leakage from the OAuth Client via Referer header";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AuthorizationCodeLeaked];

        public override string[] Countermeasures => [
            "The page rendered as a result of the OAuth authorization response and the authorization endpoint SHOULD NOT include third-party resources or links to external sites",
            "Suppress the Referer header by applying an appropriate Referrer Policy",
            "Bind the authorization code to a confidential client or PKCE challenge",
            "Invalidate authorization codes after their first use at the token endpoint; when an attempt is made to redeem a code twice, the authorization server SHOULD revoke all tokens issued previously based on that code",
            "The state value SHOULD be invalidated by the client after its first use at the redirection endpoint",
            "Use the form post response mode instead of a redirect for the authorization response"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
    }
    public class BCP_4_2_1_CredentialLeakageFromClientViaRefererImp : Threat {
        public override string Id => "BCP_4_2_1";

        public override string Description => "Credential Leakage from the OAuth Client via Referer header";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked];

        public override string[] Countermeasures => [
            "The page rendered as a result of the OAuth authorization response and the authorization endpoint SHOULD NOT include third-party resources or links to external sites",
            "Suppress the Referer header by applying an appropriate Referrer Policy",
            "Use authorization code instead of response types causing access token issuance from the authorization endpoint",
            "The state value SHOULD be invalidated by the client after its first use at the redirection endpoint",
            "Use the form post response mode instead of a redirect for the authorization response"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
    }


    public class BCP_4_2_2_CredentialLeakageFromAuthServerViaRefererAc : Threat {
        public override string Id => "BCP_4_2_2";

        public override string Description => "Credential Leakage from the Authorization Server via Referer header";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasAuthorizationCode];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AuthorizationCodeLeaked, ConsequenceTypes.StateLeaked];

        public override string[] Countermeasures => [
            "The page rendered as a result of the OAuth authorization response and the authorization endpoint SHOULD NOT include third-party resources or links to external sites",
            "Suppress the Referer header by applying an appropriate Referrer Policy",
            "Use authorization code instead of response types causing access token issuance from the authorization endpoint",
            "Bind the authorization code to a confidential client or PKCE challenge",
            "Invalidate authorization codes after their first use at the token endpoint; when an attempt is made to redeem a code twice, the authorization server SHOULD revoke all tokens issued previously based on that code",
            "The state value SHOULD be invalidated by the client after its first use at the redirection endpoint",
            "Use the form post response mode instead of a redirect for the authorization response"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
    }
    public class BCP_4_2_2_CredentialLeakageFromAuthServerViaRefererImp : Threat {
        public override string Id => "BCP_4_2_2";

        public override string Description => "Credential Leakage from the Authorization Server via Referer header";

        public override ConsequenceType[] DependsOn => [ConsequenceTypes.HasTokenInFrontChannel];

        public override ConsequenceType[] Consequences => [ConsequenceTypes.AccessTokenLeaked, ConsequenceTypes.StateLeaked];

        public override string[] Countermeasures => [
            "The page rendered as a result of the OAuth authorization response and the authorization endpoint SHOULD NOT include third-party resources or links to external sites",
            "Suppress the Referer header by applying an appropriate Referrer Policy",
            "Use authorization code instead of response types causing access token issuance from the authorization endpoint",
            "Bind the authorization code to a confidential client or PKCE challenge",
            "Invalidate authorization codes after their first use at the token endpoint; when an attempt is made to redeem a code twice, the authorization server SHOULD revoke all tokens issued previously based on that code",
            "The state value SHOULD be invalidated by the client after its first use at the redirection endpoint",
            "Use the form post response mode instead of a redirect for the authorization response"
            ];
        public override AttackerType[] Attackers => [AttackerTypes.WebAttacker];
    }
}
