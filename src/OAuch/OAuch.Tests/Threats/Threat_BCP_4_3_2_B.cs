using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_BCP_4_3_2_B : Threat {
        public Threat_BCP_4_3_2_B() {
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
        }

        public override string Id => "BCP_4_3_2_B";

        public override string Title => "Access Token in Browser History (Implicit Grant)";

        public override string Description => "In the implicit grant, a URL like client.example/redirection_endpoint#access_token=abcdef may end up in the browser history as a result of a redirect from a provider's authorization endpoint.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.3.2.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Hard;
    }
}
