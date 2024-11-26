using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_1_5 : Threat {
        public Threat_6819_4_1_5() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
            AddDependency<IdTokenFlowSupportedTest>();
            AddMitigation(Mit<RedirectUriPathMatchedTest>(1), Mit<RedirectUriFullyMatchedTest>(1), Mit<RedirectUriConfusionTest>(1), Mit<CodePollutionTest>(1));
        }

        public override string Id => "6819_4_1_5";

        public override string Title => "Open Redirectors on Client";

        public override string Description => "An open redirector is an endpoint using a parameter to automatically redirect a user agent to the location specified by the parameter value without any validation.  If the authorization server allows the client to register only part of the redirect URI, an attacker can use an open redirector operated by the client to construct a redirect URI that will pass the authorization server validation but will send the authorization 'code' or access token to an endpoint under the control of the attacker.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.1.5.";

        public override string? ExtraDescription => null;
    }
}
