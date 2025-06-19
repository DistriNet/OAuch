using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.ParEndpoint {
    public class AcceptsNewRedirectUriTest : Test {
        public override string Title => "Does the authorization server accept new redirect uri's";
        public override string Description => "This test checks whether the authorization server accepts new redirect uri's when using PAR.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(AcceptsNewRedirectUriTestResult);
    }
    public class AcceptsNewRedirectUriTestResult : TestResult<RedirectUriFullyMatchedTestInfo> {
        public AcceptsNewRedirectUriTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(AcceptsNewRedirectUriTestImplementation);
    }
    public class AcceptsNewRedirectUriTestImplementation : AcceptsNewRedirectUriImplBase {
        public AcceptsNewRedirectUriTestImplementation(TestRunContext context, AcceptsNewRedirectUriTestResult result, HasSupportedFlowsTestResult flows, IsParSupportedTestResult par) : base(context, result, flows, par) { }

        public async override Task Run() {
            await Execute(this.Context.SiteSettings);
            if (ExtraInfo.Result == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            switch (ExtraInfo.Result) {
                case RedirectUriMatchedResults.UserNotified:
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    break;
                case RedirectUriMatchedResults.RequestDenied:
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    break;
                case RedirectUriMatchedResults.ParameterIgnored:
                    Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                    break;
                case RedirectUriMatchedResults.RequestAllowed:
                    Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                    break;
            }
        }
    }
}
