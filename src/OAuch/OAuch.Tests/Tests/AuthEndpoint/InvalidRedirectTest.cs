using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class InvalidRedirectTest : Test {
        public override string Title => "Does the authorization server automatically redirect the user-agent to the invalid redirection URI";
        public override string Description => "This test checks whether the authorization server automatically redirect the user-agent to the invalid redirection URI.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesBadNoGood;
        public override Type ResultType => typeof(InvalidRedirectTestResult);
    }
    public class InvalidRedirectTestResult : TestResult<RedirectUriFullyMatchedTestInfo> {
        public InvalidRedirectTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(InvalidRedirectTestImplementation);
    }
    public class InvalidRedirectTestImplementation : TestImplementation<RedirectUriFullyMatchedTestInfo> {
        public InvalidRedirectTestImplementation(TestRunContext context, InvalidRedirectTestResult result, RedirectUriFullyMatchedTestResult fullyMatched, RedirectUriPathMatchedTestResult pathMatched, HasSupportedFlowsTestResult flows) : base(context, result, fullyMatched, pathMatched, flows) { }

        public override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null || string.IsNullOrEmpty(this.Context.SiteSettings.CallbackUri)) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            var results = new RedirectUriFullyMatchedTestInfo?[] { GetDependency<RedirectUriPathMatchedTestResult>(false)!.ExtraInfo, GetDependency<RedirectUriFullyMatchedTestResult>(false)!.ExtraInfo };

            if (results.Any(r => r != null && r.Result == RedirectUriMatchedResults.RequestDenied))
                Result.Outcome = results.Any(r => r != null && r.WrongRedirect == true && r.Result == RedirectUriMatchedResults.RequestDenied) ? TestOutcomes.SpecificationNotImplemented : TestOutcomes.SpecificationFullyImplemented;
            else
                Result.Outcome = TestOutcomes.Skipped;
            return Task.CompletedTask;
        }
    }
}
