using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Revocation;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_1_2 : Threat {
        public Threat_6819_4_1_2() {
            AddDependency<HasRefreshTokensTest>();
            AddMitigation(Mit<UsesTokenRotationTest>(1), 
                Mit<RefreshTokenRevokedAfterUseTest>(1),
                Mit<IsRefreshBoundToClientTest>(1),
                Mit<InvalidatedRefreshTokenTest>(0.3f),
                Mit<CanRefreshTokensBeRevokedTest>(0.1f));
            AddMitigation(Mit<IsRefreshAuthenticationRequiredTest>(1));
        }

        public override string Id => "6819_4_1_2";

        public override string Title => "Obtaining Refresh Tokens";

        public override string Description => "Depending on the client type, there are different ways that refresh tokens may be revealed to an attacker. An attacker may obtain the refresh tokens issued to a web application by way of overcoming the web server's security controls. On native clients, refresh tokens may be read from the local file system or the device could be stolen or cloned.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.1.2.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Hard;
    }
}
