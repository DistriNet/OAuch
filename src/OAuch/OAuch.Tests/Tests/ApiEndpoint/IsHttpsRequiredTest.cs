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
    public class IsHttpsRequiredTest : Test {
        public override string Title => "Is HTTPS required at the API endpoint";
        public override string Description => "This test checks whether the API endpoint enforces HTTPS connections.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(IsHttpsRequiredTestResult);
    }
    public class IsHttpsRequiredTestResult : TestResult {
        public IsHttpsRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsHttpsRequiredTestImplementation);
    }
    public class IsHttpsRequiredTestImplementation : TestImplementation {
        public IsHttpsRequiredTestImplementation(TestRunContext context, IsHttpsRequiredTestResult result, HasSupportedFlowsTestResult flows, TestUriSupportedTestResult testUri) : base(context, result, flows, testUri) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || HasFailed<TestUriSupportedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            if (!Context.SiteSettings.TestUri!.IsSecure()) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The test API url does not use HTTPS");
                return;
            }

            var provider = flows.CreateAccessTokenProvider(Context);
            if (provider == null) { // no provider that has the CreateTokenRequest stage
                Result.Outcome = TestOutcomes.Skipped;
                LogInfo("Could not find a working flow that accesses the token endpoint");
                return;
            }

            // we have found a working provider
            var unsafeContext = Context with
            {
                 SiteSettings = Context.SiteSettings with { 
                     TestUri = Context.SiteSettings.TestUri!.ToHttp()
                 }
            };
            var token = await provider.GetToken();
            var request = new ApiRequest(unsafeContext);
            var response = await request.Send(token);
            if (response.StatusCode.IsOk()) { // the call to the API worked
                LogInfo("The API endpoint does not enforce HTTPS");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
        }
    }
}