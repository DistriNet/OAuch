using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DocumentSupport {
    public class OpenIdSupportedTest : Test {
        public override string Title => "Is OpenID Connect supported";
        public override string Description => "This test determines whether the server supports the OpenID Connect 1.0 framework.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(OpenIdSupportedTestResult);
    }
    public class OpenIdSupportedTestResult : TestResult {
        public OpenIdSupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(OpenIdSupportedTestImplementation);
    }
    public class OpenIdSupportedTestImplementation : TestImplementation {
        public OpenIdSupportedTestImplementation(TestRunContext context, OpenIdSupportedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }
        public override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                return Task.CompletedTask;
            }

            Result.Outcome = flows.HasIdentityTokens ? TestOutcomes.SpecificationFullyImplemented : TestOutcomes.SpecificationNotImplemented;
            return Task.CompletedTask;
        }
    }
}
