using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class InvalidatedRefreshTokenTest : Test {
        public override string Title => "Is the active refresh token revoked after a multi-exchange";
        public override string Description => "This test checks if the active refresh token is revoked when the same (old) refresh token is presented twice at the token endpoint";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(InvalidatedRefreshTokenTestResult);
    }
    public class InvalidatedRefreshTokenTestResult : TestResult {
        public InvalidatedRefreshTokenTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(InvalidatedRefreshTokenTestImplementation);
    }
    public class InvalidatedRefreshTokenTestImplementation : TestImplementation {
        public InvalidatedRefreshTokenTestImplementation(TestRunContext context, InvalidatedRefreshTokenTestResult result, UsesTokenRotationTestResult utr, HasSupportedFlowsTestResult flows, RefreshTokenRevokedAfterUseTestResult rrau) : base(context, result, utr, flows, rrau) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || HasFailed<UsesTokenRotationTestResult>() || HasFailed<RefreshTokenRevokedAfterUseTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProvider(Context, (f, p) => f.HasRefreshTokens);
            if (provider == null) { // no provider with refresh tokens found
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that returns refresh tokens");
                return;
            }

            // get token
            var result = await provider.GetToken();
            if (result.RefreshToken == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Provider did not return refresh token");
                return; // should not happen
            }

            // refresh the token
            var refreshProvider = provider.CreateRefreshProvider();
            LogInfo("Waiting 2.5 seconds...");
            await Task.Delay(2500);
            var refreshedResult = await refreshProvider.RefreshToken(result.RefreshToken);
            if (refreshedResult.RefreshToken == null || refreshedResult.AccessToken == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Provider could not refresh token");
                return; // should not happen
            }
            if (refreshedResult.RefreshToken == result.RefreshToken) { // should not happen
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Provider did not use refresh token rotation");
                return;
            }

            // try to refresh the token again with the old refresh token
            LogInfo("Waiting 2.5 seconds...");
            await Task.Delay(2500);
            var badRefresh = await refreshProvider.RefreshToken(result.RefreshToken);
            if (badRefresh.AccessToken != null) { // should not happen
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Refresh tokens can be used multiple times; cannot perform test");
                return;
            }

            // let's see if the new refresh token still works
            LogInfo("Waiting 2.5 seconds...");
            await Task.Delay(2500);
            refreshedResult = await refreshProvider.RefreshToken(refreshedResult.RefreshToken);
            if (refreshedResult.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The new refresh token is revoked because the old refresh token was used multiple times");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The new refresh token is not revoked, even though the old refresh token was used multiple times");
            }
        }
    }
}
