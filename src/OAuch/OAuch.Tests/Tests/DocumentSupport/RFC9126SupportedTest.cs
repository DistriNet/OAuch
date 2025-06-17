using OAuch.Compliance.Tests.ParEndpoint;
using OAuch.Compliance.Tests.Pkce;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DocumentSupport {
    public class RFC9126SupportedTest : Test {
        public override string Title => "Does the server support RFC9126 (PAR)";
        public override string Description => "This test determines whether the server supports RFC9126 'Pushed Authorization Requests'.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RFC9126SupportedTestResult);
    }
    public class RFC9126SupportedTestResult : TestResult {
        public RFC9126SupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RFC9126SupportedTestImplementation);
    }
    public class RFC9126SupportedTestImplementation : TestImplementation {
        public RFC9126SupportedTestImplementation(TestRunContext context, RFC9126SupportedTestResult result, IsParSupportedTestResult par) : base(context, result, par) { }
        public override Task Run() {
            if (HasFailed<IsParSupportedTestResult>())
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
