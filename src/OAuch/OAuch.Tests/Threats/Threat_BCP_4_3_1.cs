using OAuch.Compliance.Tests.ApiEndpoint;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Concurrency;
using OAuch.Compliance.Tests.DeviceAuthEndpoint;
using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.IdTokens;
using OAuch.Compliance.Tests.Jwt;
using OAuch.Compliance.Tests.Pkce;
using OAuch.Compliance.Tests.Revocation;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Tokens;
using System;
using System.Collections.Generic;

namespace OAuch.Compliance.Threats {
    public class Threat_BCP_4_3_1 : Threat {
        public Threat_BCP_4_3_1() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddMitigation<MultipleCodeExchangesTest>();
            AddMitigation<SupportsPostResponseModeTest>();
        }

        public override string Id => "BCP_4_3_1";

        public override string Title => "Authorization Code in Browser History";

        public override string Description => "When a browser navigates to 'client.example/redirection_endpoint?code=abcd' as a result of a redirect from a provider's authorization endpoint, the URL including the authorization code may end up in the browser's history.  An attacker with access to the device could obtain the code and try to replay it.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.3.1.";

        public override string? ExtraDescription => null;
    }
}
