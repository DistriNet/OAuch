using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.Pkce;
using OAuch.Compliance.Tests.IdTokens;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_BCP_4_7 : Threat {
        public Threat_BCP_4_7() {
            AddDependency<CodeFlowSupportedTest>();
            AddDependency<CodeTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenFlowSupportedTest>();
            AddDependency<CodeIdTokenTokenFlowSupportedTest>();
            AddDependency<TokenFlowSupportedTest>();
            AddDependency<IdTokenTokenFlowSupportedTest>();
            AddDependency<IdTokenFlowSupportedTest>();
            AddMitigation(Mit<IsPkceRequiredTest>(1));
            AddMitigation(Mit<NoncePresentInTokenTest>(1));
        }

        public override string Id => "BCP_4_7";

        public override string Title => "Cross Site Request Forgery";

        public override string Description => "An attacker might attempt to inject a request to the redirect URI of the legitimate client on the victim's device, e.g., to cause the client to access resources under the attacker's control. This is a variant of an attack known as Cross-Site Request Forgery (CSRF).";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.7.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Reasonable;
        public override string? AliasOf => "6819_4_4_1_8";
    }
}
