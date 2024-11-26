using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_BCP_4_16 : Threat {
        public Threat_BCP_4_16() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
            AddDependency<IdTokenFlowSupportedTest>();
            AddMitigation(Mit<HasFrameOptionsTest>(1));
            AddMitigation(Mit<HasContentSecurityPolicyTest>(1));
        }

        public override string Id => "BCP_4_16";

        public override string Title => "Clickjacking";

        public override string Description => "The authorization request is susceptible to clickjacking attacks, also called user interface redressing. An attacker can use this vector to obtain the user's authentication credentials, change the scope of access granted to the client, and potentially access the user's resources.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.16.";

        public override string? ExtraDescription => null;
    }
}
