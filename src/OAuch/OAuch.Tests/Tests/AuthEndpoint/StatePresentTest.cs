using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class StatePresentTest : Test {
        public override string Title => "Is the state parameter present in the authorization response";
        public override string Description => "This test checks that the authorization server includes the state parameter in its responses.";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(StatePresentTestResult);
    }
    public class StatePresentTestResult : TestResult {
        public StatePresentTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(StatePresentTestImplementation);
    }
    public class StatePresentTestImplementation : TestImplementation {
        public StatePresentTestImplementation(TestRunContext context, StatePresentTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public override async Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProviderWithStage<GetAuthParameters, bool, Dictionary<string, string?>>(Context);
            if (provider == null) {
                LogInfo("Cannot find a working provider that uses the authorization endpoint.");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }
            var token = await provider.GetToken();
            Result.Outcome = token.AuthorizationResponse?.State == "oauch_state_var" ? TestOutcomes.SpecificationFullyImplemented : TestOutcomes.SpecificationNotImplemented;
        }
    }
}
