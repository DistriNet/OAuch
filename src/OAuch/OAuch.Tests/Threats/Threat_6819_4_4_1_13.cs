using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.DocumentSupport;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_4_1_13 : Threat {
        public Threat_6819_4_4_1_13() {
            AddDependency<OpenIdSupportedTest>();
            AddMitigation(Mit<IsCodeBoundToClientTest>(1), 
                Mit<IsClientAuthenticationRequiredTest>(1));
        }

        public override string Id => "6819_4_4_1_13";

        public override string Title => "Code Substitution (OAuth Login)";

        public override string Description => "An attacker could attempt to log into an application or web site using a victim's identity. Applications relying on identity data provided by an OAuth protected service API to login users are vulnerable to this threat. This pattern can be found in so-called 'social login' scenarios.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.1.13.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Easy;
    }
}
