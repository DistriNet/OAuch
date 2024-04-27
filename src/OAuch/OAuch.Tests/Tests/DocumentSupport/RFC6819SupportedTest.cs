using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DocumentSupport {
    public class RFC6819SupportedTest : Test {
        public override string Title => "Does the server support RFC6819 (OAuth threat model)";
        public override string Description => "This test determines whether the server supports RFC6819 'OAuth 2.0 Threat Model and Security Considerations'.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RFC6819SupportedTestResult);
    }
    public class RFC6819SupportedTestResult : TestResult {
        public RFC6819SupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RFC6819SupportedTestImplementation);
    }
    public class RFC6819SupportedTestImplementation : TestImplementation {
        public RFC6819SupportedTestImplementation(TestRunContext context, RFC6819SupportedTestResult result, HasSupportedFlowsTestResult supportedFlows) : base(context, result, supportedFlows) { }
        public override Task Run() {
            if (HasFailed<HasSupportedFlowsTestResult>())
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
