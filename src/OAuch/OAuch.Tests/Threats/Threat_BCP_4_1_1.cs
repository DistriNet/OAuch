using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_BCP_4_1_1 : Threat {
        public Threat_BCP_4_1_1() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddMitigation(Mit<RedirectUriFullyMatchedTest>(1));
            AddMitigation(Mit<RedirectUriPathMatchedTest>(1), Mit<RedirectUriConfusionTest>(1));
        }

        public override string Id => "BCP_4_1_1";

        public override string Title => "Redirect URI Validation Attacks on Authorization Code Grant";

        public override string Description => "Some authorization servers allow clients to register redirect URI patterns instead of complete redirect URIs. This approach turned out to be more complex to implement and more error prone to manage than exact redirect URI matching. Several successful attacks exploiting flaws in the pattern matching implementation or concrete configurations have been observed in the wild.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.1.1.";

        public override string? ExtraDescription => null;
    }
}
