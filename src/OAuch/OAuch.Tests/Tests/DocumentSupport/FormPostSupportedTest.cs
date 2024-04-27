using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DocumentSupport {
    public class FormPostSupportedTest : Test {
        public override string Title => "Does the server support Form Post response mode";
        public override string Description => "This test determines whether the server supports the 'OAuth 2.0 Form Post Response Mode'.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(FormPostSupportedTestResult);
    }
    public class FormPostSupportedTestResult : TestResult {
        public FormPostSupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(FormPostSupportedTestImplementation);
    }
    public class FormPostSupportedTestImplementation : TestImplementation {
        public FormPostSupportedTestImplementation(TestRunContext context, FormPostSupportedTestResult result, SupportsPostResponseModeTestResult formPost) : base(context, result, formPost) { }
        public override Task Run() {
            if (HasFailed<SupportsPostResponseModeTestResult>())
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
