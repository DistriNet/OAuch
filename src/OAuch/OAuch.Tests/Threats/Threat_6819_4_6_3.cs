using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.Tokens;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_6_3 : Threat {
        public Threat_6819_4_6_3() {
            AddDependency<TestUriSupportedTest>();
            AddMitigation(Mit<TokenTimeoutTest>(1), 
                Mit<AccessTokenEntropyMinReqTest>(1), 
                Mit<AccessTokenEntropySugReqTest>(0.1f));
        }

        public override string Id => "6819_4_6_3";

        public override string Title => "Guessing Access Tokens";

        public override string Description => "Where the token is a handle, the attacker may attempt to guess the access token values based on knowledge they have from other access tokens.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.6.3.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Reasonable;
    }
}
