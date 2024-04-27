using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Shared;
using System;

namespace OAuch.Compliance.Tests.Tokens {
    public class RefreshTokenEntropyMinReqTest : Test {
        public override string Title => "Are the refresh tokens secure (128 bits)";
        public override string Description => "This test calculates the entropy of the refresh tokens and verifies that it conforms to the minimum requirements of 128 bits";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RefreshTokenEntropyMinReqTestResult);
    }
    public class RefreshTokenEntropyMinReqTestResult : TestResult<EntropyInfo> {
        public RefreshTokenEntropyMinReqTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RefreshTokenEntropyMinReqTestImplementation);
    }
    public class RefreshTokenEntropyMinReqTestImplementation : EntropyTestImplementationBase {
        public RefreshTokenEntropyMinReqTestImplementation(TestRunContext context, RefreshTokenEntropyMinReqTestResult result, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, null, "refresh tokens", 128, t => t.RefreshToken, supportedFlows) { }
    }
}
