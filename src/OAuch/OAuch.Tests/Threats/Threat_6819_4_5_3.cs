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
    public class Threat_6819_4_5_3 : Threat {
        public Threat_6819_4_5_3() {
            AddDependency<HasRefreshTokensTest>();
            AddMitigation<RefreshTokenEntropyMinReqTest, RefreshTokenEntropySugReqTest, IsRefreshBoundToClientTest, IsRefreshAuthenticationRequiredTest>();
        }

        public override string Id => "6819_4_5_3";

        public override string Title => "Obtaining Refresh Token by Online Guessing";

        public override string Description => "An attacker may try to guess valid refresh token values and send it using the grant type 'refresh_token' in order to obtain a valid access token.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.5.3.";

        public override string? ExtraDescription => null;
    }
}
