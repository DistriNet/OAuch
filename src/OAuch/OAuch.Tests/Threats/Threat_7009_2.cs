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
    public class Threat_7009_2 : Threat {
        public Threat_7009_2() {
            AddDependency<RFC7009SupportedTest>();
            AddMitigation<IsBoundToClientTest, IsClientAuthRequiredTest>();
        }

        public override string Id => "7009_2";

        public override string Title => "Unauthorized revocation of tokens";

        public override string Description => "An authentication server that supports token revocation must verify the ownership of a token before revocation.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC7009"];

        public override string LocationInDocument => "2.1.";

        public override string? ExtraDescription => null;
    }
}
