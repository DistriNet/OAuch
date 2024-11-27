using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Tokens;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_BCP_4_14 : Threat {
        public Threat_BCP_4_14() {
            AddDependency<HasRefreshTokensTest>();
            AddMitigation(Mit<UsesTokenRotationTest>(1), 
                Mit<InvalidatedRefreshTokenTest>(0.1f), 
                Mit<RefreshTokenRevokedAfterUseTest>(1), 
                Mit<IsRefreshBoundToClientTest>(1), 
                Mit<RefreshTokenEntropyMinReqTest>(1), 
                Mit<RefreshTokenEntropySugReqTest>(0.1f), 
                Mit<IsModernTlsSupportedTest>(1), 
                Mit<IsHttpsRequiredTest>(1), 
                Mit<HasValidCertificateTest>(1));
            AddMitigation(Mit<IsRefreshBoundToClientTest>(1),
                Mit<IsRefreshAuthenticationRequiredTest>(1));
        }

        public override string Id => "BCP_4_14";

        public override string Title => "Refresh Token Protection";

        public override string Description => "Refresh tokens are an attractive target for attackers, since they represent the overall grant a resource owner delegated to a certain client. If an attacker is able to exfiltrate and successfully replay a refresh token, the attacker will be able to mint access tokens and use them to access resource servers on behalf of the resource owner.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.14.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Hard;
    }
}
