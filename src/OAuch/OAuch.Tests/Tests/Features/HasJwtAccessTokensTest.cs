using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Features {
    public class HasJwtAccessTokensTest : Test {
        public override string Title => $"Are JWT access token used";
        public override string Description => $"This test determines whether the server grants JWT access tokens.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasJwtAccessTokensTestResult);
    }
    public class HasJwtAccessTokensTestResult : TestResult {
        public HasJwtAccessTokensTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasJwtAccessTokensTestImplementation);
    }
    public class HasJwtAccessTokensTestImplementation : TestImplementation {
        public HasJwtAccessTokensTestImplementation(TestRunContext context, HasJwtAccessTokensTestResult result, HasSupportedFlowsTestResult flows)
            : base(context, result, flows) { }
        public override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || !flows.HasJwtAccessTokens)
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
