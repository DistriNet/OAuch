using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class RedirectUriCheckedTest : Test {
        public override string Title => "Is the redirect URI checked when exchanging a code";
        public override string Description => "This test checks if the token endpoint checks the redirect uri when exchanging an authorization code.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RedirectUriCheckedTestResult);
    }
    public class RedirectUriCheckedTestResult : TestResult {
        public RedirectUriCheckedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RedirectUriCheckedTestImplementation);
    }
    public class RedirectUriCheckedTestImplementation : TestImplementation {
        public RedirectUriCheckedTestImplementation(TestRunContext context, RedirectUriCheckedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

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

            var processor = new ModifyRedirectUri();
            provider.Pipeline.AddBefore<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(processor);
            var result = await provider.GetToken();
            if (result.AccessToken == null) {
                processor.RemoveUri = true;
                result = await provider.GetToken();

                if (result.AccessToken == null) {
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    LogInfo("The server did not issue an access token");
                } else {
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    LogInfo("The server issued a valid token, even though the redirect uri parameter was not present in the authorization code exchange");
                }
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The server issues a valid token, even though the redirect uri parameter in the authorization code exchange was not the same as the redirect uri in the authorization request.");
            }
        }

        private class ModifyRedirectUri : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public bool RemoveUri { get; set; }
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
                if (RemoveUri)
                    value.Remove("redirect_uri");
                else
                    value["redirect_uri"] = value["redirect_uri"]?.AddQueryParameter("computer_says", "no");
                return Task.FromResult<Dictionary<string, string?>?>(value);
            }
        }
    }
}
