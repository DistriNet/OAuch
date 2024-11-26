using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.Tokens;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_4_1_3 : Threat {
        public Threat_6819_4_4_1_3() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddMitigation(Mit<AuthorizationCodeEntropyMinReqTest>(1), Mit<AuthorizationCodeEntropySugReqTest>(1), Mit<AuthorizationCodeTimeoutTest>(1), Mit<IsCodeBoundToClientTest>(1), Mit<IsClientAuthenticationRequiredTest>(1), Mit<RedirectUriCheckedTest>(1));
        }

        public override string Id => "6819_4_4_1_3";

        public override string Title => "Online Guessing of Authorization 'codes'";

        public override string Description => "An attacker may try to guess valid authorization 'code' values and send the guessed code value using the grant type 'code' in order to obtain a valid access token.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.1.3.";

        public override string? ExtraDescription => null;
    }
}
