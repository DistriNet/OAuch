using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DPoP {
    public class IsDPoPSupportedTest : Test {
        public override string Title => "Is DPoP supported at the authorization endpoint";
        public override string Description => "This test checks whether Demonstrating Proof of Possession (DPoP) is supported on the authorization endpoint.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsDPoPSupportedTestResult);
    }
    public class IsDPoPSupportedTestResult : TestResult {
        public IsDPoPSupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsDPoPSupportedTestImplementation);
    }
    public class IsDPoPSupportedTestImplementation : TestImplementation {
        public IsDPoPSupportedTestImplementation(TestRunContext context, IsDPoPSupportedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            var prov = flows.CreateProvider(Context, mustHaveDPoPTokens: true);
            if (prov == null) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented; // no providers that support the DPoP standard
            } else {
                LogInfo($"Authorization grant type '{prov.FlowType}' generates DPoP access tokens");
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
            return Task.CompletedTask;
        }
    }
}
