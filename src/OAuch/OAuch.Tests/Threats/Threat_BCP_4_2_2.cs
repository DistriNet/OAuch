using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_BCP_4_2_2 : Threat {
        public Threat_BCP_4_2_2() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
            AddDependency<IdTokenFlowSupportedTest>();
            AddMitigation(Mit<IsCodeBoundToClientTest>(1), 
                Mit<MultipleCodeExchangesTest>(1), 
                Mit<TokenValidAfterMultiExchangeTest>(1), 
                Mit<RefreshTokenValidAfterMultiExchangeTest>(1));
            AddMitigation(Mit<ReferrerPolicyEnforcedTest>(1));
            AddMitigation(Mit<SupportsPostResponseModeTest>(1));
        }

        public override string Id => "BCP_4_2_2";

        public override string Title => "Leakage from the Authorization Server ";

        public override string Description => "An attacker can learn state from the authorization request if the authorization endpoint at the authorization server contains links or third-party content.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.2.2.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Hard;
    }
}
