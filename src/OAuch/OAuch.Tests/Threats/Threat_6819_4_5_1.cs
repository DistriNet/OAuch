using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_5_1 : Threat {
        public Threat_6819_4_5_1() {
            AddDependency<HasRefreshTokensTest>();
            AddMitigation(Mit<HasValidCertificateTest>(1), Mit<IsModernTlsSupportedTest>(1), Mit<IsHttpsRequiredTest>(1));
        }

        public override string Id => "6819_4_5_1";

        public override string Title => "Eavesdropping Refresh Tokens from Authorization Server";

        public override string Description => "An attacker may eavesdrop refresh tokens when they are transmitted between the authorization server and the client.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.5.1.";

        public override string? ExtraDescription => null;
    }
}
