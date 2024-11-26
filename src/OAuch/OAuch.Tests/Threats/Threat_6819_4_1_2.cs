using OAuch.Compliance.Tests.ApiEndpoint;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Concurrency;
using OAuch.Compliance.Tests.DeviceAuthEndpoint;
using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.IdTokens;
using OAuch.Compliance.Tests.Jwt;
using OAuch.Compliance.Tests.Pkce;
using OAuch.Compliance.Tests.Revocation;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Tokens;
using System;
using System.Collections.Generic;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_1_2 : Threat {
        public Threat_6819_4_1_2() {
            AddDependency<HasRefreshTokensTest>();
            AddMitigation<UsesTokenRotationTest, InvalidatedRefreshTokenTest, RefreshTokenRevokedAfterUseTest, IsRefreshBoundToClientTest, IsRefreshAuthenticationRequiredTest, CanRefreshTokensBeRevokedTest>();
        }

        public override string Id => "6819_4_1_2";

        public override string Title => "Obtaining Refresh Tokens";

        public override string Description => "Depending on the client type, there are different ways that refresh tokens may be revealed to an attacker. An attacker may obtain the refresh tokens issued to a web application by way of overcoming the web server's security controls. On native clients, refresh tokens may be read from the local file system or the device could be stolen or cloned.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.1.2.";

        public override string? ExtraDescription => null;
    }
}
