using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_1_1 : Threat {
        public Threat_6819_4_1_1() {
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddMitigation(Mit<RequireUserConsentTest>(1));
        }

        public override string Id => "6819_4_1_1";

        public override string Title => "Obtaining Client Secrets";

        public override string Description => "The attacker could try to get access to the secret of a particular client in order to obtain tokens on behalf of the attacked client with the privileges of that 'client_id' acting as an instance of the client.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.1.1.";

        public override string? ExtraDescription => "A malicious client can impersonate another client and obtain access to protected resources if the impersonated client fails to, or is unable to, keep its client credentials confidential.";
    }
}
