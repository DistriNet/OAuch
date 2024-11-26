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
    public class Threat_6819_4_4_1_3 : Threat {
        public Threat_6819_4_4_1_3() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddMitigation<AuthorizationCodeEntropyMinReqTest, AuthorizationCodeEntropySugReqTest, AuthorizationCodeTimeoutTest, IsCodeBoundToClientTest, IsClientAuthenticationRequiredTest, RedirectUriCheckedTest>();
        }

        public override string Id => "6819_4_4_1_3";

        public override string Title => "Online Guessing of Authorization 'codes'";

        public override string Description => "An attacker may try to guess valid authorization 'code' values and send the guessed code value using the grant type 'code' in order to obtain a valid access token.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.1.3.";

        public override string? ExtraDescription => null;
    }
}
