using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_BCP_4_3_1 : Threat {
        public Threat_BCP_4_3_1() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddMitigation(Mit<MultipleCodeExchangesTest>(1));
            AddMitigation(Mit<SupportsPostResponseModeTest>(1));
        }

        public override string Id => "BCP_4_3_1";

        public override string Title => "Authorization Code in Browser History";

        public override string Description => "When a browser navigates to 'client.example/redirection_endpoint?code=abcd' as a result of a redirect from a provider's authorization endpoint, the URL including the authorization code may end up in the browser's history.  An attacker with access to the device could obtain the code and try to replay it.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.3.1.";

        public override string? ExtraDescription => null;
    }
}
