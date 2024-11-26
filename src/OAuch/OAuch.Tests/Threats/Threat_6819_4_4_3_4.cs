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
    public class Threat_6819_4_4_3_4 : Threat {
        public Threat_6819_4_4_3_4() {
            AddDependency<PasswordFlowSupportedTest>();
            AddMitigation<HasValidCertificateTest, IsHttpsRequiredTest, IsModernTlsSupportedTest>();
        }

        public override string Id => "6819_4_4_3_4";

        public override string Title => "Obtaining User Passwords on Transport";

        public override string Description => "An attacker could attempt to eavesdrop the transmission of end-user credentials with the grant type 'password' between the client and server.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.3.4.";

        public override string? ExtraDescription => null;
    }
}
