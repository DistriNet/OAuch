using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class IsHttpsRequiredTest : Test {
        public override string Title => "Is HTTPS required at the authorization endpoint";
        public override string Description => "This test checks whether the authorization endpoint enforces HTTPS connections.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(IsHttpsRequiredTestResult);
    }
    public class IsHttpsRequiredTestResult : TestResult {
        public IsHttpsRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsHttpsRequiredTestImplementation);
    }
    public class IsHttpsRequiredTestImplementation : TestImplementation {
        public IsHttpsRequiredTestImplementation(TestRunContext context, IsHttpsRequiredTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var baseUrl = HttpHelper.GetBaseUrl(Context.SiteSettings.AuthorizationUri);
            if (baseUrl == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var fullUrl = Http.GetFullUrl(baseUrl);
            if (fullUrl.IsSecure())
                fullUrl = fullUrl.ToHttp();

            var request = HttpRequest.CreateGet(fullUrl);
            request.AllowAutoRedirect = true;
            Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            try {
                var response = await Http.SendRequest(request);
                if (response.SecurityReport.IsHttpsUsed)
                    LogInfo("The server automatically upgrades the connection to HTTPS");
                else if (response.StatusCode.IsError())
                    LogInfo("The server returned an HTTP error");
                else
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } catch {                
                // the test succeeds, because the server actively refused the connection
                LogInfo("The server actively refused the HTTP connection");
            }
        }
    }
}
