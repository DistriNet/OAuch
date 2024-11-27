using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.IdTokens;
using OAuch.Compliance.Tests.DocumentSupport;

namespace OAuch.Compliance.Threats {
    public class Threat_OIDC_16 : Threat {
        public Threat_OIDC_16() {
            AddDependency<OpenIdSupportedTest>();
            AddMitigation(Mit<ClientSecretLongEnoughTest>(0.75f), 
                Mit<IsSignedTest>(1));
        }

        public override string Id => "OIDC_16";

        public override string Title => "Falsifying identity tokens";

        public override string Description => "Resource servers that do not verify the signature of an identity token, or that accept identity tokens that are signed with weak keys, are subject to an impersonation attack.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["OIDC"];

        public override string LocationInDocument => "16.";

        public override string? ExtraDescription => null;

        public override ExecutionDifficulties ExecutionDifficulty => ExecutionDifficulties.Reasonable;
    }
}
