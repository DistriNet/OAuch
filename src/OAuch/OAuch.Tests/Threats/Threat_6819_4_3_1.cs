using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Revocation;
using OAuch.Compliance.Tests.DeviceAuthEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_3_1 : Threat {
        public Threat_6819_4_3_1() {
            AddDependency<HasSupportedFlowsTest>();
            AddMitigation(Mit<Tests.TokenEndpoint.HasValidCertificateTest>(1), Mit<Tests.TokenEndpoint.IsModernTlsSupportedTest>(1), Mit<Tests.TokenEndpoint.IsHttpsRequiredTest>(1), Mit<Tests.Revocation.IsModernTlsSupportedTest>(1), Mit<Tests.Revocation.IsRevocationEndpointSecureTest>(1), Mit<Tests.DeviceAuthEndpoint.HasValidCertificateTest>(1), Mit<Tests.DeviceAuthEndpoint.IsHttpsRequiredTest>(1), Mit<Tests.DeviceAuthEndpoint.IsModernTlsSupportedTest>(1));
        }

        public override string Id => "6819_4_3_1";

        public override string Title => "Eavesdropping Access Tokens in Transit";

        public override string Description => "Attackers may attempt to eavesdrop access tokens in transit from the authorization server to the client.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.3.1.";

        public override string? ExtraDescription => null;
    }
}
