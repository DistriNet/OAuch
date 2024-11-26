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
    public class Threat_7519_6 : Threat {
        public Threat_7519_6() {
            AddDependency<HasJwtAccessTokensTest>();
            AddMitigation<AcceptsNoneSignatureTest>();
        }

        public override string Id => "7519_6";

        public override string Title => "Unverified JWTs (resource server)";

        public override string Description => "An attacker can remove or forge the signature of a JWT to impersonate another user.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["AttsDefs"];

        public override string LocationInDocument => "";

        public override string? ExtraDescription => null;
    }
}
