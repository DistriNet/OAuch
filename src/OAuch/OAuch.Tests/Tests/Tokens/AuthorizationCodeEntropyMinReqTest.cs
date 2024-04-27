using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Shared;
using System;

namespace OAuch.Compliance.Tests.Tokens {
    public class AuthorizationCodeEntropyMinReqTest : Test {
        public override string Title => "Are the authorization codes secure (128 bits)";
        public override string Description => "This test calculates the entropy of the authorization codes and verifies that it conforms to the minimum requirements of 128 bits";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(AuthorizationCodeEntropyMinReqTestResult);
    }
    public class AuthorizationCodeEntropyMinReqTestResult : TestResult<EntropyInfo> {
        public AuthorizationCodeEntropyMinReqTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(AuthorizationCodeEntropyMinReqTestImplementation);
    }
    public class AuthorizationCodeEntropyMinReqTestImplementation : EntropyTestImplementationBase {
        public AuthorizationCodeEntropyMinReqTestImplementation(TestRunContext context, AuthorizationCodeEntropyMinReqTestResult result, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, null, "authorization codes", 128, t => t.AuthorizationCode, supportedFlows) { }
    }
}
