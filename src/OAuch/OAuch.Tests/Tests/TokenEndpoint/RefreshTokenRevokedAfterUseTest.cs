using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class RefreshTokenRevokedAfterUseTest : Test {
        public override string Title => "Is the refresh token revoked after use";
        public override string Description => "This test checks if the token endpoint revokes an old refresh token if a new one is issued to the client.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RefreshTokenRevokedAfterUseTestResult);
    }
    public class RefreshTokenRevokedAfterUseTestResult : TestResult<RefreshTokenRevokedAfterUseInfo> {
        public RefreshTokenRevokedAfterUseTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RefreshTokenRevokedAfterUseTestImplementation);
    }
    public class RefreshTokenRevokedAfterUseInfo {
        public bool UsesTokenRotation { get; set; }
    }
    public class RefreshTokenRevokedAfterUseTestImplementation : TestImplementation<RefreshTokenRevokedAfterUseInfo> {
        public RefreshTokenRevokedAfterUseTestImplementation(TestRunContext context, RefreshTokenRevokedAfterUseTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProvider(Context, (f, p) => f.HasRefreshTokens);
            if (provider == null) { // no provider with refresh tokens found
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that returns refresh tokens");
                return;
            }

            var result = await provider.GetToken();
            if (result.RefreshToken == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Provider did not return refresh token");
                return; // should not happen
            }

            var refreshProvider = provider.CreateRefreshProvider();
            LogInfo("Waiting 2.5 seconds...");
            await Task.Delay(2500);
            var refreshedResult = await refreshProvider.RefreshToken(result.RefreshToken);
            if (refreshedResult.RefreshToken == null || refreshedResult.AccessToken == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Provider could not refresh token");
                return; // should not happen
            }
            ExtraInfo.UsesTokenRotation = refreshedResult.RefreshToken != result.RefreshToken;
            if (!ExtraInfo.UsesTokenRotation) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Provider returned the same refresh token twice");
                return;
            }

            LogInfo("Waiting 2.5 seconds...");
            await Task.Delay(2500);
            // try to refresh the token again with the old refresh token
            refreshedResult = await refreshProvider.RefreshToken(result.RefreshToken);
            if (refreshedResult.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("Refresh tokens cannot be used multiple times");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("Refresh tokens can be used multiple times");
            }
        }
    }
}