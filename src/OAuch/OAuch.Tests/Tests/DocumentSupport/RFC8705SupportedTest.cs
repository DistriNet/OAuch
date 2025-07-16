using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DocumentSupport {
    public class RFC8705SupportedTest : Test {
        public override string Title => "Does the server support RFC8705 (mTLS)";
        public override string Description => "This test determines whether the server supports RFC8705 'OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens'.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RFC8705SupportedTestResult);
    }
    public class RFC8705SupportedTestResult : TestResult {
        public RFC8705SupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RFC8705SupportedTestImplementation);
    }
    public class RFC8705SupportedTestImplementation : TestImplementation {
        public RFC8705SupportedTestImplementation(TestRunContext context, RFC8705SupportedTestResult result, HasSupportedFlowsTestResult supportedFlows) : base(context, result, supportedFlows) { }
        public override Task Run() {
            if (HasFailed<HasSupportedFlowsTestResult>() || Context.SiteSettings.ClientCertificates.Count == 0)
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
