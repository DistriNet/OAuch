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
    public class Threat_6819_4_4_1_8 : Threat {
        public Threat_6819_4_4_1_8() {
            AddDependency<CodeFlowSupportedTest>();
            AddMitigation<IsPkceImplementedTest>();
            AddMitigation<NoncePresentInTokenTest>();
            AddMitigation<StatePresentTest>();
        }

        public override string Id => "6819_4_4_1_8";

        public override string Title => "CSRF Attack against redirect-uri";

        public override string Description => "Cross-site request forgery (CSRF) is a web-based attack whereby HTTP requests are transmitted from a user that the web site trusts or has authenticated. CSRF attacks on OAuth approvals can allow an attacker to obtain authorization to OAuth protected resources without the consent of the user.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.1.8.";

        public override string? ExtraDescription => null;
    }
}
