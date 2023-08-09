using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Tokens {
    public class RefreshTokenEntropySugReqTest : Test {
        public override string Title => "Are the refresh tokens secure (160 bits)";
        public override string Description => "This test calculates the entropy of the refresh tokens and verifies that it conforms to the suggested requirements of 160 bits";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(RefreshTokenEntropySugReqTestResult);
    }
    public class RefreshTokenEntropySugReqTestResult : TestResult<EntropyInfo> {
        public RefreshTokenEntropySugReqTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(RefreshTokenEntropySugReqTestImplementation);
    }
    public class RefreshTokenEntropySugReqTestImplementation : EntropyTestImplementationBase {
        public RefreshTokenEntropySugReqTestImplementation(TestRunContext context, RefreshTokenEntropySugReqTestResult result, RefreshTokenEntropyMinReqTestResult min, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, min, "refresh tokens", 160, t => t.RefreshToken, supportedFlows) { }
    }
}
