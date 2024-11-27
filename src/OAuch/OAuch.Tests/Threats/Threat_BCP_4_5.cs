using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.Pkce;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_BCP_4_5 : Threat {
        public Threat_BCP_4_5() {
            AddDependency<CodeFlowSupportedTest>();
            AddMitigation(Mit<IsPkceImplementedTest>(1), 
                Mit<HashedPkceDisabledTest>(0.3f), 
                Mit<IsPkceRequiredTest>(0.8f));
        }

        public override string Id => "BCP_4_5";

        public override string Title => "Authorization Code Injection";

        public override string Description => "In an authorization code injection attack, the attacker attempts to inject a stolen authorization code into the attacker's own session with the client. The aim is to associate the attacker's session at the client with the victim's resources or identity.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["SecBCP"];

        public override string LocationInDocument => "4.5.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Reasonable;
    }
}
