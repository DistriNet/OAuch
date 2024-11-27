using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_4_3_4 : Threat {
        public Threat_6819_4_4_3_4() {
            AddDependency<PasswordFlowSupportedTest>();
            AddMitigation(Mit<HasValidCertificateTest>(1), 
                Mit<IsHttpsRequiredTest>(1), 
                Mit<IsModernTlsSupportedTest>(1));
        }

        public override string Id => "6819_4_4_3_4";

        public override string Title => "Obtaining User Passwords on Transport";

        public override string Description => "An attacker could attempt to eavesdrop the transmission of end-user credentials with the grant type 'password' between the client and server.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.3.4.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Hard;
    }
}
