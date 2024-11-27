using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.Jwt;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_7519_6 : Threat {
        public Threat_7519_6() {
            AddDependency<HasJwtAccessTokensTest>();
            AddMitigation(Mit<AcceptsNoneSignatureTest>(1));
        }

        public override string Id => "7519_6";

        public override string Title => "Unverified JWTs (resource server)";

        public override string Description => "An attacker can remove or forge the signature of a JWT to impersonate another user.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["AttsDefs"];

        public override string LocationInDocument => "";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Easy;
    }
}
