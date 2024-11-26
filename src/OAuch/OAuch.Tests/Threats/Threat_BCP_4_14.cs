using OAuch.Compliance.Tests.Concurrency;
using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.IdTokens;
using OAuch.Compliance.Tests.Jwt;
using OAuch.Compliance.Tests.Pkce;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Tokens;
using System;
using System.Collections.Generic;

namespace OAuch.Compliance.Threats {
    public class Threat_BCP_4_14 : Threat {
        public Threat_BCP_4_14() {
            AddDependency<HasRefreshTokensTest>();
            AddMitigation<UsesTokenRotationTest, InvalidatedRefreshTokenTest, RefreshTokenRevokedAfterUseTest, IsRefreshBoundToClientTest, IsRefreshAuthenticationRequiredTest, RefreshTokenEntropyMinReqTest, RefreshTokenEntropySugReqTest, IsModernTlsSupportedTest, IsHttpsRequiredTest, HasValidCertificateTest>();
        }

        public override string Id => "BCP_4_14";

        public override string Title => "Refresh Token Protection";

        public override string Description => "Refresh tokens are an attractive target for attackers, since they represent the overall grant a resource owner delegated to a certain client. If an attacker is able to exfiltrate and successfully replay a refresh token, the attacker will be able to mint access tokens and use them to access resource servers on behalf of the resource owner.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.14.";

        public override string? ExtraDescription => null;
    }
}
