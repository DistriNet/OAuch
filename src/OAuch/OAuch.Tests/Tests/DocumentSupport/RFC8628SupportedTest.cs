using OAuch.Compliance.Tests.Features;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.DocumentSupport {
    public class RFC8628SupportedTest : Test {
        public override string Title => "Does the server support RFC8628 (device grant)";
        public override string Description => "This test determines whether the server supports RFC8628 'OAuth 2.0 Device Authorization Grant'.";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RFC8628SupportedTestResult);
    }
    public class RFC8628SupportedTestResult : TestResult {
        public RFC8628SupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RFC8628SupportedTestImplementation);
    }
    public class RFC8628SupportedTestImplementation : TestImplementation {
        public RFC8628SupportedTestImplementation(TestRunContext context, RFC8628SupportedTestResult result, DeviceFlowSupportedTestResult deviceFlow) : base(context, result, deviceFlow) { }
        public override Task Run() {
            if (HasFailed<DeviceFlowSupportedTestResult>())
                Result.Outcome = TestOutcomes.SpecificationNotImplemented;
            else
                Result.Outcome = TestOutcomes.SpecificationFullyImplemented;
            return Task.CompletedTask;
        }
    }
}
