using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_2_3 : Threat {
        public Threat_6819_4_2_3() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
            AddDependency<IdTokenFlowSupportedTest>();
            AddMitigation(Mit<RequireUserConsentTest>(1));
            AddMitigation(Mit<RedirectUriPathMatchedTest>(1), Mit<RedirectUriFullyMatchedTest>(1), Mit<RedirectUriConfusionTest>(1), Mit<CodePollutionTest>(1));
        }

        public override string Id => "6819_4_2_3";

        public override string Title => "Malicious Client Obtains Existing Authorization by Fraud";

        public override string Description => "Authorization servers may wish to automatically process authorization requests from clients that have been previously authorized by the user. When the user is redirected to the authorization server's end-user authorization endpoint to grant access, the authorization server detects that the user has already granted access to that particular client. Instead of prompting the user for approval, the authorization server automatically redirects the user back to the client. A malicious client may exploit that feature and try to obtain such an authorization 'code' instead of the legitimate client.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.2.3";

        public override string? ExtraDescription => null;
    }
}
