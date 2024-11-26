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
    public class Threat_OIDC_16 : Threat {
        public Threat_OIDC_16() {
            AddDependency<OpenIdSupportedTest>();
            AddMitigation<ClientSecretLongEnoughTest, IsSignedTest>();
        }

        public override string Id => "OIDC_16";

        public override string Title => "Falsifying identity tokens";

        public override string Description => "Resource servers that do not verify the signature of an identity token, or that accept identity tokens that are signed with weak keys, are subject to an impersonation attack.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["OIDC"];

        public override string LocationInDocument => "16.";

        public override string? ExtraDescription => null;
    }
}
