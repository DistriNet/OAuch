using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_3_3 : Threat {
        public Threat_6819_4_3_3() {
            AddDependency<HasSupportedFlowsTest>();
            AddMitigation(Mit<HasValidCertificateTest>(1), Mit<IsModernTlsSupportedTest>(1), Mit<IsHttpsRequiredTest>(1));
            AddMitigation(Mit<IsAsymmetricClientAuthenticationUsedTest>(1));
        }

        public override string Id => "6819_4_3_3";

        public override string Title => "Disclosure of Client Credentials during Transmission";

        public override string Description => "An attacker could attempt to eavesdrop the transmission of client credentials between the client and server during the client authentication process or during OAuth token requests.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.3.3.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Hard;
    }
}
