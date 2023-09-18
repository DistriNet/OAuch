using OAuch.Shared.Enumerations;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using OAuch.Compliance.Tests.Features;

namespace OAuch.Compliance.Tests.Pkce {
    public class PlainPkceDisabledTest : Test {
        public override string Title => "Is plain PKCE disabled";
        public override string Description => "This test determines whether the server disables plain PKCE.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(PlainPkceDisabledTestResult);
    }
    public class PlainPkceDisabledTestResult : TestResult {
        public PlainPkceDisabledTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(PlainPkceDisabledTestImplementation);
    }
    public class PlainPkceDisabledTestImplementation : TestImplementation {
        public PlainPkceDisabledTestImplementation(TestRunContext context, PlainPkceDisabledTestResult result, IsPkceImplementedTestResult pkce, PlainPkceTestResult plainPkce) : base(context, result, pkce, plainPkce) { }
        public override Task Run() {
            if (HasFailed<IsPkceImplementedTestResult>()) {
                Result.Outcome = TestOutcomes.Skipped;
                return Task.CompletedTask;
            }

            if (HasFailed<PlainPkceTestResult>()) {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
                LogInfo("The server disabled plain PKCE");
            } else {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
                LogInfo("The server has not disabled plain PKCE");
            }
            return Task.CompletedTask;
        }
    }
}
