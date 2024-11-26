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
    public class Threat_6819_4_4_3_1 : Threat {
        public Threat_6819_4_4_3_1() {
            AddDependency<PasswordFlowSupportedTest>();
            AddMitigation<IsPasswordFlowDisabledTest>();
        }

        public override string Id => "6819_4_4_3_1";

        public override string Title => "Accidental Exposure of Passwords at Client Site";

        public override string Description => "If the client does not provide enough protection, an attacker or disgruntled employee could retrieve the passwords for a user.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.3.1.";

        public override string? ExtraDescription => null;
    }
}
