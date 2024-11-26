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
    public class Threat_6819_4_4_2_2 : Threat {
        public Threat_6819_4_4_2_2() {
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
            AddMitigation<TokenTimeoutTest, HasCacheControlHeaderTest, HasPragmaHeaderTest, SupportsPostResponseModeTest, TokenAsQueryParameterDisabledTest>();
        }

        public override string Id => "6819_4_4_2_2";

        public override string Title => "Access Token Leak in Browser History";

        public override string Description => "An attacker could obtain the token from the browser's history. Note that this means the attacker needs access to the particular device.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.2.2.";

        public override string? ExtraDescription => null;
    }
}
