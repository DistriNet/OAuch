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
    public class Threat_6819_4_4_1_1 : Threat {
        public Threat_6819_4_4_1_1() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddMitigation<IsCodeBoundToClientTest, AuthorizationCodeTimeoutTest, MultipleCodeExchangesTest, TokenValidAfterMultiExchangeTest, RefreshTokenValidAfterMultiExchangeTest>();
        }

        public override string Id => "6819_4_4_1_1";

        public override string Title => "Eavesdropping or Leaking Authorization 'codes'";

        public override string Description => "An attacker could try to eavesdrop transmission of the authorization 'code' between the authorization server and client. Furthermore, authorization 'codes' are passed via the browser, which may unintentionally leak those codes to untrusted web sites and attackers in different ways.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.1.1.";

        public override string? ExtraDescription => null;
    }
}
