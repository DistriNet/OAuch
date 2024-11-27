using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.ApiEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_BCP_4_3_2_A : Threat {
        public Threat_BCP_4_3_2_A() {
            AddDependency<TestUriSupportedTest>();
            AddMitigation(Mit<TokenAsQueryParameterDisabledTest>(1));
        }

        public override string Id => "BCP_4_3_2_A";

        public override string Title => "Access Token in Browser History (Leaking API Request)";

        public override string Description => "An access token may end up in the browser history if a client or a web site that already has a token deliberately navigates to a page like provider.com/get_user_profile?access_token=abcdef.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.3.2.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Hard;
        public override string? AliasOf => "6819_4_6_7";
    }
}
