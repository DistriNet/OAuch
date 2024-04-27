using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class SupportsPostAuthorizationRequestsTest : Test {
        public override string Title => "Does the server support POST authentication requests";
        public override string Description => "This test checks whether the authorization server supports sending authentication parameters via a POST request.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(SupportsPostAuthorizationRequestsTestResult);
    }
    public class SupportsPostAuthorizationRequestsTestResult : TestResult {
        public SupportsPostAuthorizationRequestsTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(SupportsPostAuthorizationRequestsTestImplementation);
    }
    public class SupportsPostAuthorizationRequestsTestImplementation : TestImplementation {
        public SupportsPostAuthorizationRequestsTestImplementation(TestRunContext context, SupportsPostAuthorizationRequestsTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProviderWithStage<SendAuthorizationRedirect, string, ICallbackResult?>(Context);
            if (provider == null) { // no provider that has the SendAuthorizationRedirect stage
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that requires the authorization endpoint");
                return; // no flows that use client authentication
            }

            // make the provider use POST instead of GET
            provider.Pipeline.Replace<SendAuthorizationRedirect, string, ICallbackResult?>(new SendPostAuthorizationRedirect());

            var response = await provider.GetToken();
            Result.Outcome = (response.AccessToken != null) ? TestOutcomes.SpecificationFullyImplemented : TestOutcomes.SpecificationNotImplemented;
        }

        private class SendPostAuthorizationRedirect : Processor<string, ICallbackResult?> {
            public async override Task<ICallbackResult?> Process(string authUrl, IProvider tokenProvider, TokenResult tokenResult) {
                //var authParams = new Dictionary<string, string?>();

                // add any query parameters from the authorization url
                var authUri = new Uri(authUrl);
                var query = HttpUtility.ParseQueryString(authUri.Query);

                var encoded = EncodingHelper.Base64UrlEncode(EncodingHelper.FormUrlEncode(query.ToDictionary()!));
                var postUrl = $"/Callback/PostRedirect/{tokenProvider.Context.ManagerId:N}?values={encoded}";
                return await tokenProvider.Context.Browser.RequestCallback(postUrl);
            }
        }
    }
}
