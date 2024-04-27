using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class HasFrameOptionsTest : Test {
        public override string Title => "Authorization page has X-Frame-Options header";
        public override string Description => "This test determines whether the authorization endpoint uses the X-Frame-Options header to avoid framing of the authorization page.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasFrameOptionsTestResult);
    }
    public class HasFrameOptionsTestResult : TestResult {
        public HasFrameOptionsTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasFrameOptionsTestImplementation);
    }
    public class HasFrameOptionsTestImplementation : TestImplementation {
        public HasFrameOptionsTestImplementation(TestRunContext context, HasFrameOptionsTestResult result, HasSupportedFlowsTestResult supportedFlows) : base(context, result, supportedFlows) { }

        public override async Task Run() {
            if (HasFailed<HasSupportedFlowsTestResult>() || string.IsNullOrWhiteSpace(Context.SiteSettings.AuthorizationUri)) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var report = await Http.GetSecurityReport(Context.SiteSettings.AuthorizationUri);
            if (report.HasFrameOptions) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                LogInfo("No X-Frame-Options header present in the response for " + Context.SiteSettings.AuthorizationUri);
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            }
        }
    }
}
