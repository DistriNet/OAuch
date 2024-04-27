using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Concurrency {
    public abstract class FastRefreshTestImplementation : ConcurrencyTestImplementation {
        public FastRefreshTestImplementation(TestRunContext context, TestResult<ConcurrencyInfo> result, HasSupportedFlowsTestResult flows, TestUriSupportedTestResult testUri) : base(context, result, flows, testUri) {
            //
        }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || !flows.HasRefreshTokens) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }
            var provider = flows.CreateProvider(Context, true, false, false, true);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow with refresh tokens");
                return;
            }

            // get the refresh token
            var workingToken = await provider.GetToken();
            if (workingToken.RefreshToken == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow with a refresh token");
                return;
            }

            // run the test
            var baseToken = new TokenResult { AuthorizationResponse = ServerResponse.FromRefreshToken(workingToken) };
            var pipeline = ProviderPipeline.Start()
                .Then(new GetClaimParameters(true))
                .Then(new CreateTokenRequest());
            await RunInternal(provider, baseToken, pipeline);
        }
    }
}
