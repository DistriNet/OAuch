using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Features {
    public class HasAccessTokensTest : Test {
        public override string Title => $"Are access token supported";
        public override string Description => $"This test determines whether the server grants access tokens.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasAccessTokensTestResult);
    }
    public class HasAccessTokensTestResult : FlowSupportedTestResult {
        public HasAccessTokensTestResult(string testId) : base(testId, typeof(HasAccessTokensTestImplementation)) { }
    }
    public class HasAccessTokensTestImplementation : TestImplementation {
        public HasAccessTokensTestImplementation(TestRunContext context, HasAccessTokensTestResult result, HasSupportedFlowsTestResult flows)
            : base(context, result, flows) { }
        public override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || !flows.HasAccessTokens)
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
