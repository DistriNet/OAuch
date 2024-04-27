using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DocumentSupport {
    public class RFC6750SupportedTest : Test {
        public override string Title => "Does the server support RFC6750 (bearer token usage)";
        public override string Description => "This test determines whether the server supports RFC6750 'The OAuth 2.0 Authorization Framework: Bearer Token Usage'.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RFC6750SupportedTestResult);
    }
    public class RFC6750SupportedTestResult : TestResult {
        public RFC6750SupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RFC6750SupportedTestImplementation);
    }
    public class RFC6750SupportedTestImplementation : TestImplementation {
        public RFC6750SupportedTestImplementation(TestRunContext context, RFC6750SupportedTestResult result, TestUriSupportedTestResult testUri) : base(context, result, testUri) { }
        public override Task Run() {
            if (HasFailed<TestUriSupportedTestResult>())
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
