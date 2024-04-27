using Newtonsoft.Json;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Features {
    public class TestUriSupportedTest : Test {
        public override string Title => "Is the test URI working";

        public override string Description => "This test determines whether the test URI is working.";


        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;

        public override Type ResultType => typeof(TestUriSupportedTestResult);
    }
    public class TestUriSupportedTestResult : TestResult<TestUriSupportedExtraInfo> {
        public TestUriSupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(TestUriSupportedTestImplementation);
    }
    public class TestUriSupportedExtraInfo {
        public bool ManualAccessTokenInUrl { get; set; }
        public bool ManualAccessTokenInBody { get; set; }
        public bool ManualAccessTokenInHeader { get; set; }
        [JsonIgnore]
        public bool HasManualAccessToken => ManualAccessTokenInUrl || ManualAccessTokenInBody || ManualAccessTokenInHeader;
    }
    public class TestUriSupportedTestImplementation : TestImplementation<TestUriSupportedExtraInfo> {
        public TestUriSupportedTestImplementation(TestRunContext context, TestUriSupportedTestResult result, HasSupportedFlowsTestResult supportedFlows) : base(context, result, supportedFlows) { }
        public override async Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            if (string.IsNullOrEmpty(this.Context.SiteSettings.TestUri)) {
                LogInfo("No test URI has been set up.");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                return;
            }

            Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            try {
                var provider = flows.CreateAccessTokenProvider(Context);
                var token = await provider.GetToken();
                if (token.AccessToken == null)
                    return; // weird

                var request = new ApiRequest(Context);
                ExtraInfo.ManualAccessTokenInUrl = request.ManualAccessTokenInUrl;
                ExtraInfo.ManualAccessTokenInBody = request.ManualAccessTokenInBody;
                ExtraInfo.ManualAccessTokenInHeader = request.ManualAccessTokenInHeader;

                var response = await request.Send(token);
                if (response.StatusCode.IsOk()) { // the call to the API worked; now try the call again without an access token
                    response = await request.Send(new TokenResult());
                    if (!response.StatusCode.IsOk()) {
                        Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    }
                }
            } finally {
                await Context.Browser.SendFeatureDetected("uri", Result.Outcome == TestOutcomes.SpecificationFullyImplemented);
            }
        }
    }
}
