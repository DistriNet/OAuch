using OAuch.Compliance.Tests;
using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.Http;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Authentication;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.ApiEndpoint {
    public class IsModernTlsSupportedTest : Test {
        public override string Title => "Does the API server support a modern version of TLS";
        public override string Description => "This test determines whether the API server supports modern versions of the TLS protocol (v1.2 and higher).";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(IsModernTlsSupportedTestResult);
    }
    public class IsModernTlsSupportedTestResult : TestResult<IsModernTlsSupportedExtraInfo> {
        public IsModernTlsSupportedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(IsModernTlsSupportedTestImplementation);
    }
    public class IsModernTlsSupportedTestImplementation : IsModernTlsSupportedTestBase {
        public IsModernTlsSupportedTestImplementation(TestRunContext context, IsModernTlsSupportedTestResult result, HasSupportedFlowsTestResult supportedFlows) 
            : base(context, result, context.SiteSettings.TestUri, supportedFlows) {}
    }
}