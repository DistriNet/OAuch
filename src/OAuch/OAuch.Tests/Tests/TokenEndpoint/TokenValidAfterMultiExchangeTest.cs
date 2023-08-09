using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class TokenValidAfterMultiExchangeTest : Test {
        public override string Title => "Are tokens invalidated after exchanging the same code multiple times";
        public override string Description => "This test checks if tokens are invalidated after exchanging the same code multiple times.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(TokenValidAfterMultiExchangeTestResult);
    }
    public class TokenValidAfterMultiExchangeTestResult : TestResult {
        public TokenValidAfterMultiExchangeTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(TokenValidAfterMultiExchangeTestImplementation);
    }
    public class TokenValidAfterMultiExchangeTestImplementation : TestImplementation {
        public TokenValidAfterMultiExchangeTestImplementation(TestRunContext context, TokenValidAfterMultiExchangeTestResult result, HasSupportedFlowsTestResult flows, TestUriSupportedTestResult api, MultipleCodeExchangesTestResult multiExchange) : base(context, result, flows, api, multiExchange) { }

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
                (f, p) => f.HasAuthorizationCodes);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow with authorization codes");
                return;
            }

            var workingAccessToken = await provider.GetToken();
            if (workingAccessToken.AuthorizationCode == null || workingAccessToken.AccessToken == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow with authorization codes");
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
                var apiRequest = new ApiRequest(Context);
                var apiResponse = await apiRequest.Send(workingAccessToken);
                if (apiResponse.StatusCode.IsOk())
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                else
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                Result.Outcome = TestOutcomes.Skipped;
            }
        }
    }
}
