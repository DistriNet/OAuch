using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using OAuch.Compliance.Tests.DPoP;

namespace OAuch.Compliance.Tests.DocumentSupport {
    public class RFC9449SupportedTest : Test {
        public override string Title => "Does the server support RFC9449 (DPoP)";
        public override string Description => "This test determines whether the server supports RFC9449 'Demonstrating Proof of Possession'.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RFC9449SupportedTestResult);
    }
    public class RFC9449SupportedTestResult : TestResult {
        public RFC9449SupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RFC9449SupportedTestImplementation);
    }
    public class RFC9449SupportedTestImplementation : TestImplementation {
        public RFC9449SupportedTestImplementation(TestRunContext context, RFC9449SupportedTestResult result, IsDPoPSupportedTestResult par) : base(context, result, par) { }
        public override Task Run() {
            if (HasFailed<IsDPoPSupportedTestResult>())
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
