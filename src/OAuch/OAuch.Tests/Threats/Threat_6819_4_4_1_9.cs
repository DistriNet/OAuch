using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_6819_4_4_1_9 : Threat {
        public Threat_6819_4_4_1_9() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
            AddDependency<IdTokenFlowSupportedTest>();
            AddMitigation(Mit<HasFrameOptionsTest>(1));
            AddMitigation(Mit<HasContentSecurityPolicyTest>(1));
        }

        public override string Id => "6819_4_4_1_9";

        public override string Title => "Clickjacking Attack against Authorization";

        public override string Description => "With clickjacking, a malicious site loads the target site in a transparent iFrame overlaid on top of a set of dummy buttons that are carefully constructed to be placed directly under important buttons on the target site.  When a user clicks a visible button, they are actually clicking a button (such as an 'Authorize' button) on the hidden page.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6819"];

        public override string LocationInDocument => "4.4.1.9.";

        public override string? ExtraDescription => null;
    }
}
