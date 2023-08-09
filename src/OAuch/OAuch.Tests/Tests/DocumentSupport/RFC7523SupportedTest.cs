using OAuch.Compliance.Tests.Jwt;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DocumentSupport {
    public class RFC7523SupportedTest : Test {
        public override string Title => "Does the server support RFC7523 (JWT authentication)";
        public override string Description => "This test determines whether the server supports RFC7523 'JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants'.";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RFC7523SupportedTestResult);
    }
    public class RFC7523SupportedTestResult : TestResult {
        public RFC7523SupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RFC7523SupportedTestImplementation);
    }
    public class RFC7523SupportedTestImplementation : TestImplementation {
        public RFC7523SupportedTestImplementation(TestRunContext context, RFC7523SupportedTestResult result, SupportsJwtClientAuthenticationTestResult jwt) : base(context, result, jwt) { }
        public override Task Run() {
            if (HasFailed<SupportsJwtClientAuthenticationTestResult>())
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
