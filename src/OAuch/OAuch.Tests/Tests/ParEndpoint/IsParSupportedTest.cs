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

namespace OAuch.Compliance.Tests.ParEndpoint {
    public class IsParSupportedTest : Test {
        public override string Title => "Is PAR supported at the authorization endpoint";
        public override string Description => "This test checks whether Pushed Authorization Requests (PAR) are supported on the authorization endpoint.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsParSupportedTestResult);
    }
    public class IsParSupportedTestResult : TestResult {
        public IsParSupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsParSupportedTestImplementation);
    }
    public class IsParSupportedTestImplementation : TestImplementation {
        public IsParSupportedTestImplementation(TestRunContext context, IsParSupportedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            var prov = flows.CreateProviderWithStage<PushAuthorizationRequest, Dictionary<string, string?>, Dictionary<string, string?>>(Context);
            if (prov == null) {
                Result.Outcome = TestOutcomes.Skipped; // no providers that support the PAR standard
                return Task.CompletedTask;
            }

            if (string.IsNullOrWhiteSpace(Context.SiteSettings.ParUri)) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented; // no PAR endpoint
                return Task.CompletedTask;
            }

            // if we reach this point, there is at least one active authorization grant that supports par (implicit or auth code)
            Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
