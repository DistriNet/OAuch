using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Revocation {
    public class AccessRevokesRefreshTest : Test {
        public override string Title => "Are refresh tokens revoked after access token revocation";
        public override string Description => "This test checks whether the authorization server revokes refresh tokens after an access token from the same authorization grant is revoked.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(AccessRevokesRefreshTestResult);
    }
    public class AccessRevokesRefreshTestResult : TestResult {
        public AccessRevokesRefreshTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(AccessRevokesRefreshTestImplementation);
    }
    public class AccessRevokesRefreshTestImplementation : TestImplementation {
        public AccessRevokesRefreshTestImplementation(TestRunContext context, AccessRevokesRefreshTestResult result, HasSupportedFlowsTestResult flows, CanAccessTokensBeRevokedTestResult at, CanRefreshTokensBeRevokedTestResult rt) : base(context, result, flows, at, rt) { }

        public async override Task Run() {
            bool at = HasSucceeded<CanAccessTokensBeRevokedTestResult>(), rt = HasSucceeded<CanRefreshTokensBeRevokedTestResult>();
            if (!at || !rt) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProvider(Context, true, false, false, false);
            if (provider == null) { // no provider with refresh tokens found
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow with refresh tokens");
                return;
            }

            var result = await provider.GetToken();
            if (result.RefreshToken == null || result.AccessToken == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Provider did not return an access and refresh token");
                return; // should not happen
            }

            LogInfo("Revoking the access token...");
            var revoker = provider.CreateRevocationProvider();
            var succeeded = await revoker!.RevokeToken(result.AccessToken, false);
            if (!succeeded) {
                Result.Outcome = TestOutcomes.Skipped;
                var p = revoker.Pipeline.FindProcessor<GetServerResponseFromHttpResponse>()!;
                LogInfo($"The token revocation failed with error '{ p.Error ?? "unknown" }': '{ p.ErrorDescription ?? "no description was specified" }' (HTTP response code { (p.StatusCode.HasValue ? ((int)p.StatusCode.Value).ToString() : "unknown") })");
                return;
            }

            // revocation succeeded; see if we can still use the refresh token
            LogInfo("Waiting 5 seconds...");
            await Task.Delay(5000);

            var refresher = provider.CreateRefreshProvider();
            var refreshed = await refresher.RefreshToken(result.RefreshToken);
            if (refreshed.IsValid) {
                LogInfo("The refresh token has not been revoked");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                LogInfo("The refresh token has been revoked");
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
    }
}
