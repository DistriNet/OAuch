using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.ApiEndpoint {
    public class AreBearerTokensDisabledTest : Test {
        public override string Title => "Are the access tokens bearer tokens?";
        public override string Description => "This test determines whether the API endpoint accepts the access token as is, or whether it requires additional client authentication.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(AreBearerTokensDisabledTestResult);
    }
    public class AreBearerTokensDisabledTestResult : TestResult {
        public AreBearerTokensDisabledTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(AreBearerTokensDisabledTestImplementation);
    }
    public class AreBearerTokensDisabledTestImplementation : TestImplementation {
        public AreBearerTokensDisabledTestImplementation(TestRunContext context, AreBearerTokensDisabledTestResult result, HasSupportedFlowsTestResult supportedFlows, TestUriSupportedTestResult testUriSupported) : base(context, result, supportedFlows, testUriSupported) { }
        public override async Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || HasFailed<TestUriSupportedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            // call to TestUri has succeeded (in another test)
            // if we did not use mTLS, it must be a bearer token
            if (Context.SiteSettings.CertificateId == null) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented; // bearer token
                return;
            }

            // retry the test without mTLS
            Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            var provider = flows.CreateAccessTokenProvider(Context);
            var token = await provider.GetToken();
            if (token.AccessToken == null)
                return; // weird

            var noTlsContext = this.Context with {
                SiteSettings = this.Context.SiteSettings with {
                    CertificateId = null // do not use mTLS
                }
            };
            var request = new ApiRequest(noTlsContext);
            var response = await request.Send(token);
            if (!response.StatusCode.IsOk()) { // the call to the API didn't work; token is sender-constrained
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
    }
}