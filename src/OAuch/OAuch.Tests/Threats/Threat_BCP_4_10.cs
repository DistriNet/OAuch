using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.ApiEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_BCP_4_10 : Threat {
        public Threat_BCP_4_10() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
            AddDependency<IdTokenFlowSupportedTest>();
            AddDependency<ClientCredentialsFlowSupportedTest>();
            AddDependency<PasswordFlowSupportedTest>();
            AddMitigation(Mit<AreBearerTokensDisabledTest>(1));
        }

        public override string Id => "BCP_4_10";

        public override string Title => "Misuse of Stolen Access Tokens";

        public override string Description => "Access tokens can be stolen by an attacker in various ways. Authorization servers therefore SHOULD ensure that access tokens are sender-constrained and audience-restricted.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.10.";

        public override string? ExtraDescription => null;
    }
}
