using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.Tokens;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.ApiEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_4_2_2 : Threat {
        public Threat_6819_4_4_2_2() {
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
            AddMitigation(Mit<TokenTimeoutTest>(1), Mit<HasCacheControlHeaderTest>(1), Mit<HasPragmaHeaderTest>(1), Mit<SupportsPostResponseModeTest>(1), Mit<TokenAsQueryParameterDisabledTest>(1));
        }

        public override string Id => "6819_4_4_2_2";

        public override string Title => "Access Token Leak in Browser History";

        public override string Description => "An attacker could obtain the token from the browser's history. Note that this means the attacker needs access to the particular device.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.2.2.";

        public override string? ExtraDescription => null;
    }
}
