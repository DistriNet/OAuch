using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class RequireUserConsentTest : Test {
        public override string Title => "Is consent required";
        public override string Description => "This test checks if the authorization server requires user consent before issuing a token without client authentication.";
        public override TestResultFormatter ResultFormatter => new("PROBABLY", "PROBABLY", "PROBABLY NOT");
        public override Type ResultType => typeof(RequireUserConsentTestResult);
    }
    public class RequireUserConsentTestResult : TestResult {
        public RequireUserConsentTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RequireUserConsentTestImplementation);
    }
    public class RequireUserConsentTestImplementation : TestImplementation {
        public RequireUserConsentTestImplementation(TestRunContext context, RequireUserConsentTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProvider(Context, (f, p) => p is ImplicitTokenProvider || (p is AuthorizationCodeTokenProvider && !p.SiteSettings.IsConfidentialClient));
            if (provider == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that doesn't use client authentication");
                return;
            }

            var start = DateTime.Now;
            var token = await provider.GetToken();
            var duration = DateTime.Now.Subtract(start);
            if (token.AccessToken == null) {
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("The flow is not working");
                return;
            }

            var ms = Math.Floor(duration.TotalMilliseconds);
            LogInfo($"OAuch received a valid token from the server in {ms}ms. Any result faster than {ConsentTimeout}ms is considered an automatic authorization.");
            if (ms < ConsentTimeout) {
                LogInfo("The server automatically issued an access token without requiring client authentication.");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }

        public const int ConsentTimeout = 1500;
    }
}
