using OAuch.Compliance.Tests.ApiEndpoint;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Concurrency;
using OAuch.Compliance.Tests.DeviceAuthEndpoint;
using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.IdTokens;
using OAuch.Compliance.Tests.Jwt;
using OAuch.Compliance.Tests.Pkce;
using OAuch.Compliance.Tests.Revocation;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Tokens;
using System;
using System.Collections.Generic;

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
            AddMitigation<ClientSecretEntropyMinReqTest, ClientSecretEntropySugReqTest>();
            AddMitigation<IsAsymmetricClientAuthenticationUsedTest>();
        }

        public override string Id => "6819_4_3_5";

        public override string Title => "Obtaining Client Secret by Online Guessing";

        public override string Description => "An attacker may try to guess valid 'client_id'/secret pairs.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.3.5.";

        public override string? ExtraDescription => null;
    }
}
