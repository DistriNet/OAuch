using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.Revocation;
using OAuch.Compliance.Tests.DocumentSupport;

namespace OAuch.Compliance.Threats {
    public class Threat_7009_2 : Threat {
        public Threat_7009_2() {
            AddDependency<RFC7009SupportedTest>();
            AddMitigation(Mit<IsBoundToClientTest>(1),
                Mit<IsClientAuthRequiredTest>(0.5f));
        }

        public override string Id => "7009_2";

        public override string Title => "Unauthorized revocation of tokens";

        public override string Description => "An authentication server that supports token revocation must verify the ownership of a token before revocation.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC7009"];

        public override string LocationInDocument => "2.1.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Hard;
    }
}
