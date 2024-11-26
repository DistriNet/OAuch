using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_3_5 : Threat {
        public Threat_6819_4_3_5() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddDependency<ClientCredentialsFlowSupportedTest>();
            AddDependency<DeviceFlowSupportedTest>();
            AddDependency<PasswordFlowSupportedTest>();
            AddMitigation(Mit<ClientSecretEntropyMinReqTest>(1), Mit<ClientSecretEntropySugReqTest>(1));
            AddMitigation(Mit<IsAsymmetricClientAuthenticationUsedTest>(1));
        }

        public override string Id => "6819_4_3_5";

        public override string Title => "Obtaining Client Secret by Online Guessing";

        public override string Description => "An attacker may try to guess valid 'client_id'/secret pairs.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.3.5.";

        public override string? ExtraDescription => null;
    }
}
