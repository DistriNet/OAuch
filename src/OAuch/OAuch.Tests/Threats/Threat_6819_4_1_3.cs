using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.Tokens;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_1_3 : Threat {
        public Threat_6819_4_1_3() {
            AddDependency<HasAccessTokensTest>();
            AddMitigation(Mit<TokenTimeoutTest>(1));
        }

        public override string Id => "6819_4_1_3";

        public override string Title => "Obtaining Access Tokens";

        public override string Description => "Depending on the client type, there are different ways that access tokens may be revealed to an attacker. Access tokens could be stolen from the device if the application stores them in a storage device that is accessible to other applications.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.1.3.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Hard;
    }
}
