using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.ApiEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_6_7 : Threat {
        public Threat_6819_4_6_7() {
            AddDependency<TestUriSupportedTest>();
            AddMitigation(Mit<TokenAsQueryParameterDisabledTest>(1));
        }

        public override string Id => "6819_4_6_7";

        public override string Title => "Token Leakage via Log Files and HTTP Referrers";

        public override string Description => "If access tokens are sent via URI query parameters, such tokens may leak to log files and the HTTP 'referer'.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.6.7.";

        public override string? ExtraDescription => null;
    }
}
