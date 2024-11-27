using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_4_1_1 : Threat {
        public Threat_6819_4_4_1_1() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddMitigation(Mit<IsCodeBoundToClientTest>(1), 
                Mit<AuthorizationCodeTimeoutTest>(1), 
                Mit<MultipleCodeExchangesTest>(1), 
                Mit<TokenValidAfterMultiExchangeTest>(1), 
                Mit<RefreshTokenValidAfterMultiExchangeTest>(1));
        }

        public override string Id => "6819_4_4_1_1";

        public override string Title => "Eavesdropping or Leaking Authorization 'codes'";

        public override string Description => "An attacker could try to eavesdrop transmission of the authorization 'code' between the authorization server and client. Furthermore, authorization 'codes' are passed via the browser, which may unintentionally leak those codes to untrusted web sites and attackers in different ways.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.1.1.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Hard;
    }
}
