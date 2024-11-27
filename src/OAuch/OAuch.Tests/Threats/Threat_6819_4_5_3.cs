using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.Tokens;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_5_3 : Threat {
        public Threat_6819_4_5_3() {
            AddDependency<HasRefreshTokensTest>();
            AddMitigation(Mit<RefreshTokenEntropyMinReqTest>(1), 
                Mit<RefreshTokenEntropySugReqTest>(0.1f),
                Mit<IsRefreshBoundToClientTest>(1));
            AddMitigation(Mit<IsRefreshBoundToClientTest>(1), 
                Mit<IsRefreshAuthenticationRequiredTest>(1));
        }

        public override string Id => "6819_4_5_3";

        public override string Title => "Obtaining Refresh Token by Online Guessing";

        public override string Description => "An attacker may try to guess valid refresh token values and send it using the grant type 'refresh_token' in order to obtain a valid access token.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.5.3.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Reasonable;
    }
}
