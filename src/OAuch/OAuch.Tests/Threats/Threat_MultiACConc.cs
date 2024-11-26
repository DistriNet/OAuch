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
    public class Threat_MultiACConc : Threat {
        public Threat_MultiACConc() {
            AddDependency<CodeFlowSupportedTest>();
            AddMitigation<MultipleCodeExchangesTest, SingleFastACExchangeTest, MultiFastACExchangeTest, RefreshTokenRevokedAfterUseTest, SingleFastRefreshTest, MultiFastRefreshTest, ConcurrentTokensRevokedTest>();
        }

        public override string Id => "MultiACConc";

        public override string Title => "Multiple authorization codes concurrency bugs";

        public override string Description => "Concurrency issues can result in an authorization code being used multiple times.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6749"];

        public override string LocationInDocument => "";

        public override string? ExtraDescription => "A malicious client can exchange an authorization code multiple times.";
    }
}
