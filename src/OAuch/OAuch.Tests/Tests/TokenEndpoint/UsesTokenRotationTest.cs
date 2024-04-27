using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class UsesTokenRotationTest : Test {
        public override string Title => "Is refresh token rotation used";
        public override string Description => "This test checks if the token endpoint uses refresh token rotation";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(UsesTokenRotationTestResult);
    }
    public class UsesTokenRotationTestResult : TestResult {
        public UsesTokenRotationTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(UsesTokenRotationTestImplementation);
    }
    public class UsesTokenRotationTestImplementation : TestImplementation {
        public UsesTokenRotationTestImplementation(TestRunContext context, UsesTokenRotationTestResult result, RefreshTokenRevokedAfterUseTestResult rtr, HasSupportedFlowsTestResult flows) : base(context, result, rtr, flows) { }

        public override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            var rtr = GetDependency<RefreshTokenRevokedAfterUseTestResult>(false);
            if (rtr == null || flows == null || !flows.HasRefreshTokens) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            if (rtr.ExtraInfo?.UsesTokenRotation == true) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                return Task.CompletedTask;
            }

            if (Context.SiteSettings.Certificates.Count > 0) {
                // sender-constrained tokens do not need token rotation
                Result.Outcome = TestOutcomes.Skipped;
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            }
            return Task.CompletedTask;
        }
    }
}
