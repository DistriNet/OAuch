using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class IsModernTlsSupportedTest : Test {
        public override string Title => "Does the token server support a modern version of TLS";
        public override string Description => "This test determines whether the token server supports modern versions of the TLS protocol (v1.2 and higher).";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsModernTlsSupportedTestResult);
    }
    public class IsModernTlsSupportedTestResult : TestResult<IsModernTlsSupportedExtraInfo> {
        public IsModernTlsSupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsModernTlsSupportedTestImplementation);
    }
    public class IsModernTlsSupportedTestImplementation : IsModernTlsSupportedTestBase {
        public IsModernTlsSupportedTestImplementation(TestRunContext context, IsModernTlsSupportedTestResult result, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, context.SiteSettings.TokenUri, supportedFlows) { }
    }
}
