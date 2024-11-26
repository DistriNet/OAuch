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
    public class Threat_OIDC_2 : Threat {
        public Threat_OIDC_2() {
            AddDependency<OpenIdSupportedTest>();
            AddMitigation<CodeHashValidTest, HasAuthorizedPartyTest, HasAzpForMultiAudienceTest, HasCorrectAudienceTest, HasCorrectIssuerTest, HasCorrectMacTest, HasRequiredClaimsTest, IsAccessTokenHashCorrectTest, IsAccessTokenHashPresentTest, IsAuthorizationCodeHashPresentTest, KeyReferencesTest, NoncePresentInTokenTest>();
        }

        public override string Id => "OIDC_2";

        public override string Title => "Abuse of incomplete/invalid identity tokens";

        public override string Description => "An attacker may attempt to re-use an identity token that was acquired for another client or for another authorization session.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["OIDC"];

        public override string LocationInDocument => "2.";

        public override string? ExtraDescription => null;
    }
}
