using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.ApiEndpoint {
    public class SupportsAuthorizationHeaderTest : Test {
        public override string Title => "Is the authorization header supported";
        public override string Description => "This test determines whether the API endpoint supports authentication via the Authorization header.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(SupportsAuthorizationHeaderTestResult);
    }
    public class SupportsAuthorizationHeaderTestResult : TestResult {
        public SupportsAuthorizationHeaderTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(SupportsAuthorizationHeaderTestImplementation);
    }
    public class SupportsAuthorizationHeaderTestImplementation : TestImplementation {
        public SupportsAuthorizationHeaderTestImplementation(TestRunContext context, SupportsAuthorizationHeaderTestResult result, HasSupportedFlowsTestResult supportedFlows, TestUriSupportedTestResult testUri) : base(context, result, supportedFlows, testUri) { }
        public override Task Run() {
            var testUri = GetDependency<TestUriSupportedTestResult>(true);
            if (testUri == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            if (testUri.ExtraInfo?.HasManualAccessToken == false) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            }
            return Task.CompletedTask;
        }
    }
}
