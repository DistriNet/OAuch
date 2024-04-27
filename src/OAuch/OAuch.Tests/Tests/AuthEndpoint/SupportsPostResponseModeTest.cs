using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class SupportsPostResponseModeTest : Test {
        public override string Title => "Does the server support Post Form response mode";
        public override string Description => "This test checks whether the authorization server supports the Form Post response mode.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(SupportsPostResponseModeTestResult);
    }
    public class SupportsPostResponseModeTestResult : TestResult {
        public SupportsPostResponseModeTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(SupportsPostResponseModeTestImplementation);
    }
    public class SupportsPostResponseModeTestImplementation : TestImplementation {
        public SupportsPostResponseModeTestImplementation(TestRunContext context, SupportsPostResponseModeTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var formPostContext = Context with {
                SiteSettings = Context.SiteSettings with {
                    ResponseMode = ResponseModes.FormPost
                }
            };

            var provider = flows.CreateProviderWithStage<GetAuthParameters, bool, Dictionary<string, string?>>(formPostContext);
            if (provider == null) { // no provider that has the GetAuthParameters stage
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that uses the authorization endpoint");
                return;
            }

            var proc = new InspectResponse();
            provider.Pipeline.AddBefore<GetServerResponseFromCallback, ICallbackResult?, ServerResponse>(proc);

            var response = await provider.GetToken();
            if (proc.HasIgnoredParameter != null && proc.HasIgnoredParameter.Value) {
                LogInfo("The server returned a valid token, but did not send it as a POST response.");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else if (response.AccessToken != null) {
                LogInfo("The server returned a valid token as a POST response.");
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                LogInfo("The request failed.");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            }
        }

        private class InspectResponse : Processor<ICallbackResult?, ICallbackResult?> {
            public bool? HasIgnoredParameter { get; set; }
            public override Task<ICallbackResult?> Process(ICallbackResult? callback, IProvider tokenProvider, TokenResult tokenResult) {
                if (callback != null) {
                    var response = ServerResponse.FromCallbackResult(callback, ResponseModes.FormPost, ResponseModes.FormPost, tokenProvider.Log);
                    if (!response.IsValid) {
                        if (ServerResponse.FromCallbackResult(callback, ResponseModes.AutoDetect, ResponseModes.AutoDetect, tokenProvider.Log).IsValid)
                            this.HasIgnoredParameter = true;
                    }
                }
                return Task.FromResult(callback);
            }
        }
    }
}