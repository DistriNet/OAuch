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
    public class Threat_6819_4_6_6 : Threat {
        public Threat_6819_4_6_6() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddDependency<ClientCredentialsFlowSupportedTest>();
            AddDependency<DeviceFlowSupportedTest>();
            AddDependency<PasswordFlowSupportedTest>();
            AddMitigation<HasCacheControlHeaderTest, HasPragmaHeaderTest>();
        }

        public override string Id => "6819_4_6_6";

        public override string Title => "Leak of Confidential Data in HTTP Proxies";

        public override string Description => "An OAuth HTTP authentication scheme as discussed in RFC6749 is optional.  However, RFC2616 relies on the Authorization and WWW-Authenticate headers to distinguish authenticated content so that it can be protected.  Proxies and caches, in particular, may fail to adequately protect requests not using these headers.  For example, private authenticated content may be stored in (and thus be retrievable from) publicly accessible caches.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.6.6.";

        public override string? ExtraDescription => null;
    }
}
