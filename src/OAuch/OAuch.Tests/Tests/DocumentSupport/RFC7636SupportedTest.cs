using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Pkce;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DocumentSupport {
    public class RFC7636SupportedTest : Test {
        public override string Title => "Does the server support RFC7636 (PKCE)";
        public override string Description => "This test determines whether the server supports RFC7636 'Proof Key for Code Exchange by OAuth Public Clients'.";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RFC7636SupportedTestResult);
    }
    public class RFC7636SupportedTestResult : TestResult {
        public RFC7636SupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RFC7636SupportedTestImplementation);
    }
    public class RFC7636SupportedTestImplementation : TestImplementation {
        public RFC7636SupportedTestImplementation(TestRunContext context, RFC7636SupportedTestResult result, IsPkceImplementedTestResult pkce) : base(context, result, pkce) { }
        public override Task Run() {
            if (HasFailed<IsPkceImplementedTestResult>())
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
