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
    public class CanRefreshTokensBeRevokedTest : Test {
        public override string Title => "Can refresh tokens be revoked";
        public override string Description => "This test checks if the revocation endpoint supports revoking refresh tokens.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(CanRefreshTokensBeRevokedTestResult);
    }
    public class CanRefreshTokensBeRevokedTestResult : TestResult {
        public CanRefreshTokensBeRevokedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(CanRefreshTokensBeRevokedTestImplementation);
    }
    public class CanRefreshTokensBeRevokedTestImplementation : TestImplementation {
        public CanRefreshTokensBeRevokedTestImplementation(TestRunContext context, CanRefreshTokensBeRevokedTestResult result, HasSupportedFlowsTestResult flows, RFC7009SupportedTestResult revocation) : base(context, result, flows, revocation) { }

        public async override Task Run() {
            if (HasFailed<RFC7009SupportedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || !flows.HasRefreshTokens) {
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
            if (result.RefreshToken == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Provider did not return a refresh token");
                return; // should not happen
            }

            var revoker = provider.CreateRevocationProvider();
            var succeeded = await revoker!.RevokeToken(result.RefreshToken, true);
            if (!succeeded) {
                var p = revoker.Pipeline.FindProcessor<GetServerResponseFromHttpResponse>()!;
                LogInfo($"The token revocation failed with error '{ p.Error ?? "unknown" }': '{ p.ErrorDescription ?? "no description was specified" }' (HTTP response code { (p.StatusCode.HasValue ? ((int)p.StatusCode.Value).ToString() : "unknown") })");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                return;
            }

            // revocation succeeded; see if we can use it
            LogInfo("Waiting 5 seconds...");
            await Task.Delay(5000);

            var refresher = provider.CreateRefreshProvider();
            var refreshed = await refresher.RefreshToken(result.RefreshToken);
            if (refreshed.IsValid) {
                LogInfo("The server reported that the refresh token was revoked, but it is still working");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                LogInfo("The refresh token was successfully revoked");
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
    }
}
