using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Settings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DocumentSupport {
    public class RFC7009SupportedTest : Test {
        public override string Title => "Does the server support RFC7009 (token revocation)";
        public override string Description => "This test determines whether the server supports RFC7009 'OAuth 2.0 Token Revocation'.";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RFC7009SupportedTestResult);
    }
    public class RFC7009SupportedTestResult : TestResult {
        public RFC7009SupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RFC7009SupportedTestImplementation);
    }
    public class RFC7009SupportedTestImplementation : TestImplementation {
        public RFC7009SupportedTestImplementation(TestRunContext context, RFC7009SupportedTestResult result, TestUriSupportedTestResult testUri) : base(context, result, testUri) { }
        public override Task Run() {
            if (string.IsNullOrWhiteSpace(Context.SiteSettings.RevocationUri)) {
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            } else {
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            }
            return Task.CompletedTask;
        }
    }
}
