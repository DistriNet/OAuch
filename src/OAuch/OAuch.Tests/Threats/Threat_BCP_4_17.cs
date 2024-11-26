using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_BCP_4_17 : Threat {
        public Threat_BCP_4_17() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
            AddDependency<IdTokenFlowSupportedTest>();
            AddMitigation(Mit<AutomaticRedirectInvalidScopeTest>(1), Mit<AutomaticRedirectInvalidResponseTypeTest>(1));
        }

        public override string Id => "BCP_4_17";

        public override string Title => "Authorization Server Redirecting to Phishing Site";

        public override string Description => "An attacker could utilize a correctly registered redirect URI to perform phishing attacks. The authorization server SHOULD only automatically redirect the user agent if it trusts the redirect URI. If the URI is not trusted, the authorization server MAY inform the user and rely on the user to make the correct decision.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.17.";

        public override string? ExtraDescription => null;
    }
}
