using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Features;

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
            AddMitigation(Mit<HasCacheControlHeaderTest>(1), Mit<HasPragmaHeaderTest>(1));
        }

        public override string Id => "6819_4_6_6";

        public override string Title => "Leak of Confidential Data in HTTP Proxies";

        public override string Description => "An OAuth HTTP authentication scheme as discussed in RFC6749 is optional.  However, RFC2616 relies on the Authorization and WWW-Authenticate headers to distinguish authenticated content so that it can be protected.  Proxies and caches, in particular, may fail to adequately protect requests not using these headers.  For example, private authenticated content may be stored in (and thus be retrievable from) publicly accessible caches.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.6.6.";

        public override string? ExtraDescription => null;
    }
}
