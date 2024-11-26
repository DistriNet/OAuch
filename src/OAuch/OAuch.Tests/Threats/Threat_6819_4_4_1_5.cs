using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_4_1_5 : Threat {
        public Threat_6819_4_4_1_5() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddMitigation(Mit<IsCodeBoundToClientTest>(1), Mit<IsClientAuthenticationRequiredTest>(1));
        }

        public override string Id => "6819_4_4_1_5";

        public override string Title => "Authorization 'code' Phishing";

        public override string Description => "A hostile party could impersonate the client site and get access to the authorization 'code'. This could be achieved using DNS or ARP spoofing. This applies to clients, which are web applications; thus, the redirect URI is not local to the host where the user's browser is running.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.1.5.";

        public override string? ExtraDescription => null;
    }
}
