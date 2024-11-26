using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_5_4 : Threat {
        public Threat_6819_4_5_4() {
            AddDependency<HasRefreshTokensTest>();
            AddMitigation(Mit<HasValidCertificateTest>(1));
        }

        public override string Id => "6819_4_5_4";

        public override string Title => "Refresh Token Phishing by Counterfeit Authorization Server";

        public override string Description => "An attacker could try to obtain valid refresh tokens by proxying requests to the authorization server.  Given the assumption that the authorization server URL is well-known at development time or can at least be obtained from a well-known resource server, the attacker must utilize some kind of spoofing in order to succeed.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.5.4.";

        public override string? ExtraDescription => null;
    }
}
