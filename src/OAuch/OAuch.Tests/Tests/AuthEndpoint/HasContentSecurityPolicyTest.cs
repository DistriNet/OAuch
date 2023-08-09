using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class HasContentSecurityPolicyTest : Test {
        public override string Title => "Authorization page has Content Security Policy";
        public override string Description => "This test determines whether the authorization endpoint uses a content security policy to avoid framing of the authorization page.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(HasContentSecurityPolicyTestResult);
    }
    public class HasContentSecurityPolicyTestResult : TestResult {
        public HasContentSecurityPolicyTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(HasContentSecurityPolicyTestImplementation);
    }
    public class HasContentSecurityPolicyTestImplementation : TestImplementation {
        public HasContentSecurityPolicyTestImplementation(TestRunContext context, HasContentSecurityPolicyTestResult result, HasSupportedFlowsTestResult supportedFlows) : base(context, result, supportedFlows) { }

        public override async Task Run() {
            if (HasFailed<HasSupportedFlowsTestResult>() || string.IsNullOrWhiteSpace(Context.SiteSettings.AuthorizationUri)) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var report = await Http.GetSecurityReport(Context.SiteSettings.AuthorizationUri);
            if (report.HasContentSecurityPolicy) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            } else {
                LogInfo("The authorization page does not specify a content security policy either in the HTTP headers or as a HTML meta tag.");
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            }
        }
    }
}
