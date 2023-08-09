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

namespace OAuch.Compliance.Tests.ApiEndpoint {
    public class CacheControlTest : Test {
        public override string Title => "Is Cache-Control header sent when the access token is used in the URI";
        public override string Description => "This test checks whether the Cache-Control header is sent when a call is made to the API endpoint that passes the access token via the URL.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(CacheControlTestResult);
    }
    public class CacheControlTestResult : TestResult {
        public CacheControlTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(CacheControlTestImplementation);
    }
    public class CacheControlTestImplementation : TestImplementation {
        public CacheControlTestImplementation(TestRunContext context, CacheControlTestResult result, HasSupportedFlowsTestResult flows, TokenAsQueryParameterTestResult tokenSupported) : base(context, result, flows, tokenSupported) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || HasFailed<TokenAsQueryParameterTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateAccessTokenProvider(Context);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that issues access tokens");
                return;
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
                var value = response.Headers.Get("Cache-Control");
                if (value == null) {
                    LogInfo("The server did not send a Cache-Control header");
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                } else {
                    var safeValues = new string[] { "private", "no-store" };
                    var parts = value.Split(',');
                    if (safeValues.Any(sv => parts.Any(p => p.Trim().ToLower() == sv))) {
                        LogInfo("The server sent a Cache-Control header");
                        Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    } else {
                        LogInfo("The server sent a Cache-Control header, but it was not 'private' or 'no-store'");
                        Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    }
                }
            } else {
                // server did not return a valid response
                Result.Outcome = TestOutcomes.Skipped;
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