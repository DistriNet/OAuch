using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class RefreshTokenValidAfterMultiExchangeTest : Test {
        public override string Title => "Are refresh tokens invalidated after exchanging the same authorization code multiple times";
        public override string Description => "This test checks if refresh tokens are invalidated after exchanging the same authorization code multiple times.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RefreshTokenValidAfterMultiExchangeTestResult);
    }
    public class RefreshTokenValidAfterMultiExchangeTestResult : TestResult {
        public RefreshTokenValidAfterMultiExchangeTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RefreshTokenValidAfterMultiExchangeTestImplementation);
    }
    public class RefreshTokenValidAfterMultiExchangeTestImplementation : TestImplementation {
        public RefreshTokenValidAfterMultiExchangeTestImplementation(TestRunContext context, RefreshTokenValidAfterMultiExchangeTestResult result, HasSupportedFlowsTestResult flows, TestUriSupportedTestResult api, MultipleCodeExchangesTestResult multiExchange) : base(context, result, flows, api, multiExchange) { }

        public async override Task Run() {
            if (HasFailed<TestUriSupportedTestResult>() || HasFailed<MultipleCodeExchangesTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProviderWithStage<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(this.Context,
                (f, p) => f.HasAuthorizationCodes, true, true);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow with authorization codes and refresh tokens");
                return;
            }

            var workingAccessToken = await provider.GetToken();
            if (workingAccessToken.AuthorizationCode == null || workingAccessToken.RefreshToken == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow with authorization codes and refresh tokens");
                return;
            }

            // do multi exchange
            var tempResult = new TokenResult { AuthorizationResponse = workingAccessToken.AuthorizationResponse };
            var pipeline = ProviderPipeline.Start()
                .Then(new GetClaimParameters())
                .Then(new AddRedirectUri())
                .Then(new AddPKCEVerifier(Context.SiteSettings.PKCEDefault))
                .Then(new CreateTokenRequest())
                .Then(new SendRequest(UriTypes.TokenUri))
                .Then(new GetServerResponseFromHttpResponse())
                .FinishTokenResponse();
            var success = await pipeline.Run(provider, tempResult);
            if (!success || tempResult.TokenResponse?.AccessToken == null) {
                // multi exchange was denied; now see if access token is still working
                LogInfo("Waiting 5 seconds...");
                await Task.Delay(5000);
                var refreshProvider = provider.CreateRefreshProvider();
                var refreshedResult = await refreshProvider.RefreshToken(workingAccessToken.RefreshToken);
                if (refreshedResult.RefreshToken == null || refreshedResult.AccessToken == null) {
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    LogInfo("The refresh token was revoked");
                } else {
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    LogInfo("The refresh token was not revoked");
                }
            } else {
                // multi exchange was allowed; should not happen here
                Result.Outcome = TestOutcomes.Skipped;
            }
        }
    }
}
