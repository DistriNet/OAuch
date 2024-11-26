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
    public class Threat_BCP_4_8 : Threat {
        public Threat_BCP_4_8() {
            AddDependency<IsPkceImplementedTest>();
            AddMitigation<IsPkceDowngradeDetectedTest, IsPkcePlainDowngradeDetectedTest, IsPkceTokenDowngradeDetectedTest>();
        }

        public override string Id => "BCP_4_8";

        public override string Title => "PKCE Downgrade Attack";

        public override string Description => "An authorization server that supports PKCE but does not make its use mandatory for all flows can be susceptible to a PKCE downgrade attack.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.8.";

        public override string? ExtraDescription => null;
    }
}
