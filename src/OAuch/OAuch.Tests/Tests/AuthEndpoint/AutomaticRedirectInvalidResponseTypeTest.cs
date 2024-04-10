using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Protocols.OAuth2;
using OAuch.Shared.Enumerations;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class AutomaticRedirectInvalidResponseTypeTest : Test {
        public override string Title => "Are invalid response types automatically redirected back?";
        public override string Description => "This test checks if the authorization server redirects the user agent back to the redirect URI when an invalid response type is used.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(AutomaticRedirectInvalidResponseTypeTestResult);
    }
    public class AutomaticRedirectInvalidResponseTypeTestResult : TestResult {
        public AutomaticRedirectInvalidResponseTypeTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(AutomaticRedirectInvalidResponseTypeTestImplementation);
    }
    public class AutomaticRedirectInvalidResponseTypeTestImplementation : TestImplementation {
        public AutomaticRedirectInvalidResponseTypeTestImplementation(TestRunContext context, AutomaticRedirectInvalidResponseTypeTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProviderWithStage<GetAuthParameters, bool, Dictionary<string, string?>>(this.Context);
            if (provider == null) {
                LogInfo("Could not find a provider that uses the authorization server");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var processor = new ChangeResponseTypeParameter();
            provider.Pipeline.AddAfter<GetAuthParameters, bool, Dictionary<string, string?>>(processor);

            var result = await provider.GetToken();
            if (result.IsValid) {
                LogInfo("The authorization server accepts invalid response types");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }
            if (!result.AuthorizationResponse!.WasCallbackStalled) {
                LogInfo("The authorization server automatically redirects the user to the redirect URI when an invalid response type is used");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else { // the user had to click on the stalled test button
                // retry the test, but now with prompt=none
                processor.RequestNoPrompt = true;
                result = await provider.GetToken();
                if (result.IsValid) {
                    LogInfo("The authorization server accepts invalid response types");
                    Result.Outcome = TestOutcomes.Skipped;
                    return;
                }
                if (result.AuthorizationResponse!.WasCallbackStalled) {
                    LogInfo("The authorization server does not automatically redirect the user agent when an invalid response type is used");
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                } else {
                    LogInfo("The authorization server automatically redirects the user to the redirect URI when an invalid response type and prompt=none is used");
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                }
            }
        }
        public class ChangeResponseTypeParameter : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
            public bool RequestNoPrompt { get; set; }
            public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider tokenProvider, TokenResult tokenResult) {
                value["response_type"] = "oauch-invalid-responsetype";
                if (RequestNoPrompt)
                    value.Add("prompt", "none"); // add OpenID no prompt

                return Task.FromResult<Dictionary<string, string?>?>(value);
            }
        }
    }
}

