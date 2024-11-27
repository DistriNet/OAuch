using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.Pkce;

namespace OAuch.Compliance.Threats {
    public class Threat_BCP_4_8 : Threat {
        public Threat_BCP_4_8() {
            AddDependency<IsPkceImplementedTest>();
            AddMitigation(Mit<IsPkceDowngradeDetectedTest>(1),
                Mit<IsPkcePlainDowngradeDetectedTest>(0.5f), 
                Mit<IsPkceTokenDowngradeDetectedTest>(1));
        }

        public override string Id => "BCP_4_8";

        public override string Title => "PKCE Downgrade Attack";

        public override string Description => "An authorization server that supports PKCE but does not make its use mandatory for all flows can be susceptible to a PKCE downgrade attack.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.8.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Easy;
    }
}
