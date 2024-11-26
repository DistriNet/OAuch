using OAuch.Compliance.Tests.Concurrency;
using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.IdTokens;
using OAuch.Compliance.Tests.Jwt;
using OAuch.Compliance.Tests.Pkce;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Tokens;
using System;
using System.Collections.Generic;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_3_3 : Threat {
        public Threat_6819_4_3_3() {
            AddDependency<HasSupportedFlowsTest>();
            AddMitigation<HasValidCertificateTest, IsModernTlsSupportedTest, IsHttpsRequiredTest>();
            AddMitigation<IsAsymmetricClientAuthenticationUsedTest>();
        }

        public override string Id => "6819_4_3_3";

        public override string Title => "Disclosure of Client Credentials during Transmission";

        public override string Description => "An attacker could attempt to eavesdrop the transmission of client credentials between the client and server during the client authentication process or during OAuth token requests.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.3.3.";

        public override string? ExtraDescription => null;
    }
}
