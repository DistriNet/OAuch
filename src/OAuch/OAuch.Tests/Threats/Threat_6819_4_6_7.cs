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
    public class Threat_6819_4_6_7 : Threat {
        public Threat_6819_4_6_7() {
            AddDependency<TestUriSupportedTest>();
            AddMitigation<TokenAsQueryParameterDisabledTest>();
        }

        public override string Id => "6819_4_6_7";

        public override string Title => "Token Leakage via Log Files and HTTP Referrers";

        public override string Description => "If access tokens are sent via URI query parameters, such tokens may leak to log files and the HTTP 'referer'.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.6.7.";

        public override string? ExtraDescription => null;
    }
}
