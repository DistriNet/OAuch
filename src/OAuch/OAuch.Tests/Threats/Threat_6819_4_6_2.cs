using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.ApiEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_6_2 : Threat {
        public Threat_6819_4_6_2() {
            AddDependency<TestUriSupportedTest>();
            AddMitigation(Mit<HasValidCertificateTest>(1), Mit<IsModernTlsSupportedTest>(1), Mit<IsHttpsRequiredTest>(1));
        }

        public override string Id => "6819_4_6_2";

        public override string Title => "Replay of Authorized Resource Server Requests";

        public override string Description => "An attacker could attempt to replay valid requests in order to obtain or to modify/destroy user data.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.6.2.";

        public override string? ExtraDescription => null;
    }
}
