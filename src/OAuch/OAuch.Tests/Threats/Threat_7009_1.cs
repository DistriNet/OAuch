using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.Revocation;
using OAuch.Compliance.Tests.DocumentSupport;

namespace OAuch.Compliance.Threats {
    public class Threat_7009_1 : Threat {
        public Threat_7009_1() {
            AddDependency<RFC7009SupportedTest>();
            AddMitigation(//Mit<AccessRevokesRefreshTest>(1), 
                Mit<CanAccessTokensBeRevokedTest>(0.5f), 
                Mit<CanRefreshTokensBeRevokedTest>(1), 
                Mit<RefreshRevokesAccessTest>(0.5f));
        }

        public override string Id => "7009_1";

        public override string Title => "Abuse of revoked tokens";

        public override string Description => "Leaked (and potentially long-lived) access or refesh tokens that cannot be revoked may enable an attacker to impersonate a user.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC7009"];

        public override string LocationInDocument => "2.1.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Hard;
    }
}
