using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Features {
    public class TokenAsQueryParameterTest : Test {
        public override string Title => "Can the token be passed via the query";
        public override string Description => "This test determines whether the API endpoint accepts the access token via a URL query parameter.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(TokenAsQueryParameterTestResult);
    }
    public class TokenAsQueryParameterTestResult : TestResult {
        public TokenAsQueryParameterTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(TokenAsQueryParameterTestImplementation);
    }
    public class TokenAsQueryParameterTestImplementation : TestImplementation {
        public TokenAsQueryParameterTestImplementation(TestRunContext context, TokenAsQueryParameterTestResult result, HasSupportedFlowsTestResult supportedFlows, TestUriSupportedTestResult testUri) : base(context, result, supportedFlows, testUri) { }
        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            var testUri = GetDependency<TestUriSupportedTestResult>(true);
            if (flows == null || testUri == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            if (testUri.ExtraInfo?.ManualAccessTokenInUrl == true) {
                LogInfo("The site is configured to include the access token in the URL of the API call");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                return;
            }
            if (testUri.ExtraInfo?.ManualAccessTokenInBody == true || testUri.ExtraInfo?.ManualAccessTokenInHeader == true) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateAccessTokenProvider(Context);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that issues access tokens");
                return; // no flows that use client authentication
            }

            var token = await provider.GetToken();
            if (token.AccessToken == null) {
                LogInfo("Access token request failed");
                Result.Outcome = TestOutcomes.Skipped; // weird
                return;
            }

            var request = new InsecureApiRequest(Context);
            var response = await request.Send(token);
            if (response.StatusCode.IsOk()) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented; // this is a feature, not a countermeasure
            } else { 
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            }
        }
        private class InsecureApiRequest : ApiRequest {
            public InsecureApiRequest(TestRunContext context) : base(context) { }

            protected override HttpRequest GetRequest(string uri, TokenResult token) {
                var req = base.GetRequest(uri, token);
                req.Headers.Remove(HttpRequestHeaders.Authorization);
                req.Headers.Add(HttpRequestHeaders.CacheControl, "no-store");
                req.Url = req.Url.AddQueryParameter("access_token", token.AccessToken ?? "");
                return req;
            }
        }
    }
}