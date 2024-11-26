using System;
using System.Collections.Generic;
using OAuch.Compliance.Tests.TokenEndpoint;
using OAuch.Compliance.Tests.Concurrency;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Threats {
    public class Threat_MultiACConc : Threat {
        public Threat_MultiACConc() {
            AddDependency<CodeFlowSupportedTest>();
            AddMitigation(Mit<MultipleCodeExchangesTest>(1), Mit<SingleFastACExchangeTest>(1), Mit<MultiFastACExchangeTest>(1), Mit<RefreshTokenRevokedAfterUseTest>(1), Mit<SingleFastRefreshTest>(1), Mit<MultiFastRefreshTest>(1), Mit<ConcurrentTokensRevokedTest>(1));
        }

        public override string Id => "MultiACConc";

        public override string Title => "Multiple authorization codes concurrency bugs";

        public override string Description => "Concurrency issues can result in an authorization code being used multiple times.";

        public override OAuthDocument Document => ComplianceDatabase.Documents["RFC6749"];

        public override string LocationInDocument => "";

        public override string? ExtraDescription => "A malicious client can exchange an authorization code multiple times.";
    }
}
