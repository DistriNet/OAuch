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
    public class Threat_6819_4_6_3 : Threat {
        public Threat_6819_4_6_3() {
            AddDependency<TestUriSupportedTest>();
            AddMitigation<TokenTimeoutTest, AccessTokenEntropyMinReqTest, AccessTokenEntropySugReqTest>();
        }

        public override string Id => "6819_4_6_3";

        public override string Title => "Guessing Access Tokens";

        public override string Description => "Where the token is a handle, the attacker may attempt to guess the access token values based on knowledge they have from other access tokens.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.6.3.";

        public override string? ExtraDescription => null;
    }
}
