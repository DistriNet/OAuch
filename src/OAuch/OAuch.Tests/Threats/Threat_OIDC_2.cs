using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.IdTokens;
using OAuch.Compliance.Tests.DocumentSupport;

namespace OAuch.Compliance.Threats {
    public class Threat_OIDC_2 : Threat {
        public Threat_OIDC_2() {
            AddDependency<OpenIdSupportedTest>();
            AddMitigation(Mit<CodeHashValidTest>(1), Mit<HasAuthorizedPartyTest>(1), Mit<HasAzpForMultiAudienceTest>(1), Mit<HasCorrectAudienceTest>(1), Mit<HasCorrectIssuerTest>(1), Mit<HasCorrectMacTest>(1), Mit<HasRequiredClaimsTest>(1), Mit<IsAccessTokenHashCorrectTest>(1), Mit<IsAccessTokenHashPresentTest>(1), Mit<IsAuthorizationCodeHashPresentTest>(1), Mit<KeyReferencesTest>(1), Mit<NoncePresentInTokenTest>(1));
        }

        public override string Id => "OIDC_2";

        public override string Title => "Abuse of incomplete/invalid identity tokens";

        public override string Description => "An attacker may attempt to re-use an identity token that was acquired for another client or for another authorization session.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["OIDC"];

        public override string LocationInDocument => "2.";

        public override string? ExtraDescription => null;
    }
}
