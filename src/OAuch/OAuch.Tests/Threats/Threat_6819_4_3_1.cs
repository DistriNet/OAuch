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
    public class Threat_6819_4_3_1 : Threat {
        public Threat_6819_4_3_1() {
            AddDependency<HasSupportedFlowsTest>();
            AddMitigation<Tests.TokenEndpoint.HasValidCertificateTest, Tests.TokenEndpoint.IsModernTlsSupportedTest, Tests.TokenEndpoint.IsHttpsRequiredTest, Tests.Revocation.IsModernTlsSupportedTest, IsRevocationEndpointSecureTest, Tests.DeviceAuthEndpoint.HasValidCertificateTest, Tests.DeviceAuthEndpoint.IsHttpsRequiredTest, Tests.DeviceAuthEndpoint.IsModernTlsSupportedTest>();
        }

        public override string Id => "6819_4_3_1";

        public override string Title => "Eavesdropping Access Tokens in Transit";

        public override string Description => "Attackers may attempt to eavesdrop access tokens in transit from the authorization server to the client.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.3.1.";

        public override string? ExtraDescription => null;
    }
}
