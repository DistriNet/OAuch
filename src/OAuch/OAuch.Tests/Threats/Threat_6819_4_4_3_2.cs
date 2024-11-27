using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_4_3_2 : Threat {
        public Threat_6819_4_4_3_2() {
            AddDependency<PasswordFlowSupportedTest>();
            AddMitigation(Mit<IsPasswordFlowDisabledTest>(1));
        }

        public override string Id => "6819_4_4_3_2";

        public override string Title => "Client Obtains Scopes without End-User Authorization";

        public override string Description => "All interaction with the resource owner is performed by the client. Thus it might, intentionally or unintentionally, happen that the client obtains a token with scope unknown for, or unintended by, the resource owner.  For example, the resource owner might think the client needs and acquires read-only access to its media storage only but the client tries to acquire an access token with full access permissions.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.3.2.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Easy;
    }
}
