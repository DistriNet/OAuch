using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.Jwt;

namespace OAuch.Compliance.Threats {
    public class Threat_7523 : Threat {
        public Threat_7523() {
            AddDependency<SupportsJwtClientAuthenticationTest>();
            AddMitigation(Mit<IsSignatureCheckedTest>(1), 
                Mit<IsSignatureRequiredTest>(1), 
                Mit<HasAudienceClaimTest>(1), 
                Mit<HasIssuerClaimTest>(1), 
                Mit<HasSubjectClaimTest>(1),
                Mit<IsExpirationCheckedTest>(1), 
                Mit<IsIssuedAtCheckedTest>(1), 
                Mit<IsJwtReplayDetectedTest>(1), 
                Mit<IsNotBeforeCheckedTest>(1));
        }

        public override string Id => "7523";

        public override string Title => "Unverified JWTs for client authentication";

        public override string Description => "An attacker can use an expired or otherwise invalid token to impersonate another user.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC7523"];

        public override string LocationInDocument => "4.1.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Reasonable;
    }
}
