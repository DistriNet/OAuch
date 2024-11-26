using OAuch.Compliance.Tests.ApiEndpoint;
using OAuch.Compliance.Tests.Concurrency;
using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.IdTokens;
using OAuch.Compliance.Tests.Jwt;
using OAuch.Compliance.Tests.Pkce;
using OAuch.Compliance.Tests.Tokens;
using System;
using System.Collections.Generic;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_6_1 : Threat {
        public Threat_6819_4_6_1() {
            AddDependency<TestUriSupportedTest>();
            AddMitigation<HasValidCertificateTest, IsModernTlsSupportedTest, IsHttpsRequiredTest, TokenTimeoutTest>();
        }

        public override string Id => "6819_4_6_1";

        public override string Title => "Eavesdropping Access Tokens on Transport";

        public override string Description => "An attacker could try to obtain a valid access token on transport between the client and resource server.  As access tokens are shared secrets between the authorization server and resource server, they should be treated with the same care as other credentials (e.g., end-user passwords).";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.6.1.";

        public override string? ExtraDescription => null;
    }
}
