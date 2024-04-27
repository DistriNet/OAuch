using OAuch.Compliance.Tests.DocumentSupport;
using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Revocation {
    public class CanAccessTokensBeRevokedTest : Test {
        public override string Title => "Can access tokens be revoked";
        public override string Description => "This test checks if the revocation endpoint supports revoking access tokens.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(CanAccessTokensBeRevokedTestResult);
    }
    public class CanAccessTokensBeRevokedTestResult : TestResult {
        public CanAccessTokensBeRevokedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(CanAccessTokensBeRevokedTestImplementation);
    }
    public class CanAccessTokensBeRevokedTestImplementation : TestImplementation {
        public CanAccessTokensBeRevokedTestImplementation(TestRunContext context, CanAccessTokensBeRevokedTestResult result, HasSupportedFlowsTestResult flows, RFC7009SupportedTestResult revocation) : base(context, result, flows, revocation) { }

        public async override Task Run() {
            if (HasFailed<RFC7009SupportedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateAccessTokenProvider(Context);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow");
                return;
            }

            var result = await provider.GetToken();
            if (result.AccessToken == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Provider did not return an access token");
                return; // should not happen
            }

            var revoker = provider.CreateRevocationProvider();
            var succeeded = await revoker!.RevokeToken(result.AccessToken, false);
            if (!succeeded) {
                var p = revoker.Pipeline.FindProcessor<GetServerResponseFromHttpResponse>();
                if (p == null)
                    LogInfo($"The token revocation failed.");
                else
                    LogInfo($"The token revocation failed with error '{p.Error ?? "unknown"}': '{p.ErrorDescription ?? "no description was specified"}' (HTTP response code {(p.StatusCode.HasValue ? ((int)p.StatusCode.Value).ToString() : "unknown")})");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                return;
            }

            // revocation succeeded; see if we can use it
            LogInfo("Waiting 5 seconds...");
            await Task.Delay(5000);

            var request = new ApiRequest(Context);
            var response = await request.Send(result);
            if (response.StatusCode.IsOk()) {
                LogInfo("The server reported that the access token was revoked, but it is still working");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                LogInfo("The access token was successfully revoked");
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
    }
}
