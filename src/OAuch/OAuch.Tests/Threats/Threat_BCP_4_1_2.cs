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
    public class Threat_BCP_4_1_2 : Threat {
        public Threat_BCP_4_1_2() {
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddMitigation<RedirectUriFullyMatchedTest>();
            AddMitigation<RedirectUriPathMatchedTest, RedirectUriConfusionTest, FragmentFixTest>();
        }

        public override string Id => "BCP_4_1_2";

        public override string Title => "Redirect URI Validation Attacks on Implicit Grant";

        public override string Description => "Implicit clients can be subject to an attack that utilizes the fact that user agents re-attach fragments to the destination URL of a redirect if the location header does not contain a fragment. This allows circumvention even of very narrow redirect URI patterns, but not strict URL matching.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.1.2.";

        public override string? ExtraDescription => null;
    }
}
