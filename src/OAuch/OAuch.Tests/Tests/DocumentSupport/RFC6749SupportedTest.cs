using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DocumentSupport {
    public class RFC6749SupportedTest : Test {
        public override string Title => "Does the server support RFC6749 (OAuth authorization framework)";
        public override string Description => "This test determines whether the server supports RFC6749 'The OAuth 2.0 Authorization Framework'.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RFC6749SupportedTestResult);
    }
    public class RFC6749SupportedTestResult : TestResult {
        public RFC6749SupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RFC6749SupportedTestImplementation);
    }
    public class RFC6749SupportedTestImplementation : TestImplementation {
        public RFC6749SupportedTestImplementation(TestRunContext context, RFC6749SupportedTestResult result, HasSupportedFlowsTestResult supportedFlows, TestUriSupportedTestResult testUri) : base(context, result, supportedFlows, testUri) {
            // we don't really need TestUriSupportedTestResult here, but we add a requirement to it
            // because we want the TestUriSupported test to be run as soon as possible
        }
        public override Task Run() {
            if (HasFailed<HasSupportedFlowsTestResult>())
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
