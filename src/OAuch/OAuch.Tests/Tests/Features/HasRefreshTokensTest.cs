using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Features {
    public class HasRefreshTokensTest : Test {
        public override string Title => $"Are refresh tokens supported";
        public override string Description => $"This test determines whether the server grants refresh tokens.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasRefreshTokensTestResult);
    }
    public class HasRefreshTokensTestResult : FlowSupportedTestResult {
        public HasRefreshTokensTestResult(string testId) : base(testId, typeof(HasRefreshTokensTestImplementation)) { }
    }
    public class HasRefreshTokensTestImplementation : TestImplementation {
        public HasRefreshTokensTestImplementation(TestRunContext context, HasRefreshTokensTestResult result, HasSupportedFlowsTestResult flows)
            : base(context, result, flows) { }
        public override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || !flows.HasRefreshTokens)
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
