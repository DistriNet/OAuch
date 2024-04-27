using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Shared;
using System;

namespace OAuch.Compliance.Tests.ApiEndpoint {
    public class AreStrongCiphersEnabledTest : Test {
        public override string Title => "Does the API server support only secure cipher suites";
        public override string Description => "This test determines whether the API server supports only secure cipher suites in TLS v1.2.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(AreStrongCiphersEnabledTestResult);
    }
    public class AreStrongCiphersEnabledTestResult : TestResult {
        public AreStrongCiphersEnabledTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(AreStrongCiphersEnabledTestImplementation);
    }
    public class AreStrongCiphersEnabledTestImplementation : AreStrongCiphersEnabledTestImplementationBase {
        public AreStrongCiphersEnabledTestImplementation(TestRunContext context, AreStrongCiphersEnabledTestResult result, HasSupportedFlowsTestResult supportedFlows, IsModernTlsSupportedTestResult modernTls, IsDeprecatedTlsSupportedTestResult deprecatedTls)
            : base(context, result, context.SiteSettings.AuthorizationUri, true, supportedFlows, modernTls, deprecatedTls) { }
    }
}
