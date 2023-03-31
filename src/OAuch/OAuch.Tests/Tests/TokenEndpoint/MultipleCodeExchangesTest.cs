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
    public class MultipleCodeExchangesTest : Test {
        public override string Title => "Can codes be exchanged multiple times";
        public override string Description => "This test checks if the token server allows authorization codes to be used multiple times.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(MultipleCodeExchangesTestResult);
    }
    public class MultipleCodeExchangesTestResult : TestResult {
        public MultipleCodeExchangesTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(MultipleCodeExchangesTestImplementation);
    }
    public class MultipleCodeExchangesTestImplementation : TestImplementation {
        public MultipleCodeExchangesTestImplementation(TestRunContext context, MultipleCodeExchangesTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
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

            ValidToken = await provider.GetToken();
            if (ValidToken.AuthorizationCode == null || ValidToken.AccessToken == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow with authorization codes");
                return;
            }
            ValidToken.TokenResponse = null;

            var pipeline = ProviderPipeline.Start()
                .Then(new GetClaimParameters())
                .Then(new AddRedirectUri())
                .Then(new AddPKCEVerifier(Context.SiteSettings.PKCEDefault))
                .Then(new CreateTokenRequest())
                .Then(new SendRequest(UriTypes.TokenUri))
                .Then(new GetServerResponseFromHttpResponse())
                .FinishTokenResponse();
            var success = await pipeline.Run(provider, ValidToken);
            if (!success || ValidToken.TokenResponse?.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("Token endpoint did not accept authorization code twice.");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("Token endpoint accepted authorization code twice.");
            }
        }
        protected TokenResult? ValidToken { get; set; }
    }
}
