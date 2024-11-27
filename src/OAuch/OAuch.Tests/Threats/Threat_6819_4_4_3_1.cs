using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_4_3_1 : Threat {
        public Threat_6819_4_4_3_1() {
            AddDependency<PasswordFlowSupportedTest>();
            AddMitigation(Mit<IsPasswordFlowDisabledTest>(1));
        }

        public override string Id => "6819_4_4_3_1";

        public override string Title => "Accidental Exposure of Passwords at Client Site";

        public override string Description => "If the client does not provide enough protection, an attacker or disgruntled employee could retrieve the passwords for a user.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.3.1.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Easy;
    }
}
