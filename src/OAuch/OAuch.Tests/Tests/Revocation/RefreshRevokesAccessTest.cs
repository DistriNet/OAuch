using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
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
    public class RefreshRevokesAccessTest : Test {
        public override string Title => "Are access tokens revoked after refresh token revocation";
        public override string Description => "This test checks whether the authorization server revokes access tokens after a refresh token from the same authorization grant is revoked.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RefreshRevokesAccessTestResult);
    }
    public class RefreshRevokesAccessTestResult : TestResult {
        public RefreshRevokesAccessTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RefreshRevokesAccessTestImplementation);
    }
    public class RefreshRevokesAccessTestImplementation : TestImplementation {
        public RefreshRevokesAccessTestImplementation(TestRunContext context, RefreshRevokesAccessTestResult result, HasSupportedFlowsTestResult flows, CanAccessTokensBeRevokedTestResult at, CanRefreshTokensBeRevokedTestResult rt) : base(context, result, flows, at, rt) { }

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
            var succeeded = await revoker!.RevokeToken(result.RefreshToken, true);
            if (!succeeded) {
                Result.Outcome = TestOutcomes.Skipped;
                var p = revoker.Pipeline.FindProcessor<GetServerResponseFromHttpResponse>()!;
                LogInfo($"The token revocation failed with error '{ p.Error ?? "unknown" }': '{ p.ErrorDescription ?? "no description was specified" }' (HTTP response code { (p.StatusCode.HasValue ? ((int)p.StatusCode.Value).ToString() : "unknown") })");
                return;
            }

            // revocation succeeded; see if we can still use the refresh token
            LogInfo("Waiting 5 seconds...");
            await Task.Delay(5000);

            var request = new ApiRequest(Context);
            var response = await request.Send(result);
            if (response.StatusCode.IsOk()) {
                LogInfo("The server did not revoke the access token");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                LogInfo("The access token was revoked");
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
    }
}
