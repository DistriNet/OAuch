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
using System.Web;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class IsGetSupportedTest : Test {
        public override string Title => "Does the token server support GET requests";
        public override string Description => "This test checks if the token server supports GET requests.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(IsGetSupportedTestResult);
    }
    public class IsGetSupportedTestResult : TestResult {
        public IsGetSupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsGetSupportedTestImplementation);
    }
    public class IsGetSupportedTestImplementation : TestImplementation {
        public IsGetSupportedTestImplementation(TestRunContext context, IsGetSupportedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProviderWithStage<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(this.Context);
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that uses the token server");
                return;
            }

            var processor = new GetTokenRequest();
            provider.Pipeline.AddAfter<CreateTokenRequest, Dictionary<string, string?>, HttpRequest>(processor);

            var result = await provider.GetToken();
            if (result.AccessToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("Token server accepts GET requests");
            }
        }
        public class GetTokenRequest : Processor<HttpRequest, HttpRequest> {
            public override Task<HttpRequest?> Process(HttpRequest value, IProvider tokenProvider, TokenResult tokenResult) {
                var pars = EncodingHelper.EncodedFormToDictionary(value.Content);
                var builder = new UriBuilder(value.Url);
                var query = HttpUtility.ParseQueryString(builder.Query);
                foreach (var key in pars.Keys) {
                    query[key] = pars[key];
                }
                builder.Query = query.ToString();
                value.Url = builder.ToString();
                value.Method = HttpMethods.Get;
                value.Content = [];
                return Task.FromResult<HttpRequest?>(value);
            }
        }
    }
}
