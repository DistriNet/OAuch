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
    public class Threat_BCP_4_2_2 : Threat {
        public Threat_BCP_4_2_2() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
            AddDependency<IdTokenFlowSupportedTest>();
            AddMitigation<IsCodeBoundToClientTest, MultipleCodeExchangesTest, TokenValidAfterMultiExchangeTest, RefreshTokenValidAfterMultiExchangeTest>();
            AddMitigation<ReferrerPolicyEnforcedTest>();
            AddMitigation<SupportsPostResponseModeTest>();
        }

        public override string Id => "BCP_4_2_2";

        public override string Title => "Leakage from the Authorization Server ";

        public override string Description => "An attacker can learn state from the authorization request if the authorization endpoint at the authorization server contains links or third-party content.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.2.2.";

        public override string? ExtraDescription => null;
    }
}
