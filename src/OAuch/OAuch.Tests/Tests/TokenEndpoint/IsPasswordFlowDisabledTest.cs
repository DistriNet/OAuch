using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class IsPasswordFlowDisabledTest : Test {
        public override string Title => $"Is the password flow disabled";
        public override string Description => $"This test determines whether the password flow is disabled.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsPasswordFlowDisabledTestResult);
    }
    public class IsPasswordFlowDisabledTestResult : FlowSupportedTestResult {
        public IsPasswordFlowDisabledTestResult(string testId) : base(testId, typeof(IsPasswordFlowDisabledTestImplementation)) { }
    }
    public class IsPasswordFlowDisabledTestImplementation : TestImplementation {
        public IsPasswordFlowDisabledTestImplementation(TestRunContext context, IsPasswordFlowDisabledTestResult result, PasswordFlowSupportedTestResult pw)
            : base(context, result, pw) { }
        public override Task Run() {
            var pw = GetDependency<PasswordFlowSupportedTestResult>(true);
            if (pw == null)
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            return Task.CompletedTask;
        }
    }
}
