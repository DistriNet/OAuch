using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_4_3_3 : Threat {
        public Threat_6819_4_4_3_3() {
            AddDependency<PasswordFlowSupportedTest>();
            AddMitigation(Mit<IsPasswordFlowDisabledTest>(1));
        }

        public override string Id => "6819_4_4_3_3";

        public override string Title => "Client Obtains Refresh Token through Automatic Authorization";

        public override string Description => "All interaction with the resource owner is performed by the client. Thus it might, intentionally or unintentionally, happen that the client obtains a long-term authorization represented by a refresh token even if the resource owner did not intend so.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.3.3.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Easy;
    }
}
