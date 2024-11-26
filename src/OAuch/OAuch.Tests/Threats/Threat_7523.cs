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
    public class Threat_7523 : Threat {
        public Threat_7523() {
            AddDependency<SupportsJwtClientAuthenticationTest>();
            AddMitigation<IsSignatureCheckedTest, IsSignatureRequiredTest, HasAudienceClaimTest, HasIssuerClaimTest, HasSubjectClaimTest, IsExpirationCheckedTest, IsIssuedAtCheckedTest, IsJwtReplayDetectedTest, IsNotBeforeCheckedTest>();
        }

        public override string Id => "7523";

        public override string Title => "Unverified JWTs for client authentication";

        public override string Description => "An attacker can use an expired or otherwise invalid token to impersonate another user.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC7523"];

        public override string LocationInDocument => "4.1.";

        public override string? ExtraDescription => null;
    }
}
