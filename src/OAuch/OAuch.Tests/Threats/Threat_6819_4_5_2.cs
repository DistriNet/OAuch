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
    public class Threat_6819_4_5_2 : Threat {
        public Threat_6819_4_5_2() {
            AddDependency<HasRefreshTokensTest>();
            AddMitigation<IsRefreshBoundToClientTest, IsRefreshAuthenticationRequiredTest>();
        }

        public override string Id => "6819_4_5_2";

        public override string Title => "Obtaining Refresh Token from Authorization Server Database";

        public override string Description => "This threat is applicable if the authorization server stores refresh tokens as handles in a database.  An attacker may obtain refresh tokens from the authorization server's database by gaining access to the database or launching a SQL injection attack.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.5.2.";

        public override string? ExtraDescription => null;
    }
}
