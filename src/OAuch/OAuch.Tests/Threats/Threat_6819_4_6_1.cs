using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.ApiEndpoint;
using OAuch.Compliance.Tests.Tokens;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_6_1 : Threat {
        public Threat_6819_4_6_1() {
            AddDependency<TestUriSupportedTest>();
            AddMitigation(Mit<HasValidCertificateTest>(1), 
                Mit<IsModernTlsSupportedTest>(1), 
                Mit<IsHttpsRequiredTest>(1), 
                Mit<TokenTimeoutTest>(1));
        }

        public override string Id => "6819_4_6_1";

        public override string Title => "Eavesdropping Access Tokens on Transport";

        public override string Description => "An attacker could try to obtain a valid access token on transport between the client and resource server.  As access tokens are shared secrets between the authorization server and resource server, they should be treated with the same care as other credentials (e.g., end-user passwords).";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.6.1.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Hard;
    }
}
