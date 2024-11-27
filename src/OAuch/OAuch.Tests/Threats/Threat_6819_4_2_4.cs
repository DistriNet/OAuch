using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_2_4 : Threat {
        public Threat_6819_4_2_4() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
            AddDependency<IdTokenFlowSupportedTest>();
            AddMitigation(Mit<RedirectUriPathMatchedTest>(1), 
                Mit<RedirectUriConfusionTest>(1), 
                Mit<CodePollutionTest>(1), 
                Mit<InvalidRedirectTest>(1));
            AddMitigation(Mit<RedirectUriFullyMatchedTest>(1));
        }

        public override string Id => "6819_4_2_4";

        public override string Title => "Open Redirector";

        public override string Description => "An attacker could use the end-user authorization endpoint and the redirect URI parameter to abuse the authorization server as an open redirector. An open redirector is an endpoint using a parameter to automatically redirect a user agent to the location specified by the parameter value without any validation. An attacker could utilize a user's trust in an authorization server to launch a phishing attack.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.2.4";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Easy;
    }
}
