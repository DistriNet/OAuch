using OAuch.Compliance.Tests.AuthEndpoint;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DocumentSupport {
    public class RFC9101SupportedTest : Test {
        public override string Title => "Does the server support RFC9101 (JAR)";
        public override string Description => "This test determines whether the server supports RFC9101 'JWT-Secured Authorization Requests'.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RFC9101SupportedTestResult);
    }
    public class RFC9101SupportedTestResult : TestResult {
        public RFC9101SupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RFC9101SupportedTestImplementation);
    }
    public class RFC9101SupportedTestImplementation : TestImplementation {
        public RFC9101SupportedTestImplementation(TestRunContext context, RFC9101SupportedTestResult result, IsJarSupportedTestResult jar) : base(context, result, jar) { }
        public override Task Run() {
            if (HasFailed<IsJarSupportedTestResult>())
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
