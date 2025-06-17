using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.ParEndpoint {
    public class IsParRequiredTest : Test {
        public override string Title => "Is PAR required at the authorization endpoint";
        public override string Description => "This test checks whether Pushed Authorization Requests (PAR) are required on the authorization endpoint.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsParRequiredTestResult);
    }
    public class IsParRequiredTestResult : TestResult {
        public IsParRequiredTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsParRequiredTestImplementation);
    }
    public class IsParRequiredTestImplementation : TestImplementation {
        public IsParRequiredTestImplementation(TestRunContext context, IsParRequiredTestResult result, HasSupportedFlowsTestResult flows, IsParSupportedTestResult par) : base(context, result, flows, par) { }

        public async override Task Run() {
            if (HasFailed<IsParSupportedTestResult>()) { // no PAR support
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var prov = flows.CreateProviderWithStage<PushAuthorizationRequest, Dictionary<string, string?>, Dictionary<string, string?>>(Context);
            if (prov == null) {
                Result.Outcome = TestOutcomes.Skipped; // no providers that support the PAR standard (weird, should not happen here, because we know PAR is supported)
                return;
            }
            prov.Pipeline.Replace<PushAuthorizationRequest, Dictionary<string, string?>, Dictionary<string, string?>>(new DummyPushAuthorizationRequest());

            var result = await prov.GetToken();
            if (result.AccessToken == null && result.IdentityToken == null) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The request failed without PAR");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The request succeeded without PAR");
            }
        }
    }

    public class DummyPushAuthorizationRequest : Processor<Dictionary<string, string?>, Dictionary<string, string?>> {
        public override Task<Dictionary<string, string?>?> Process(Dictionary<string, string?> value, IProvider provider, TokenResult tokenResult) {
            return Task.FromResult(value); // do nothing (i.e., disable PAR)
        }
    }
}
