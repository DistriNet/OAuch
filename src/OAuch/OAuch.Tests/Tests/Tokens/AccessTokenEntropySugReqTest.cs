using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Tokens {
    public class AccessTokenEntropySugReqTest : Test {
        public override string Title => "Are the access tokens secure (160 bits)";
        public override string Description => "This test calculates the entropy of the access tokens and verifies that it conforms to the suggested requirements of 160 bits";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(AccessTokenEntropySugReqTestResult);
    }
    public class AccessTokenEntropySugReqTestResult : TestResult<EntropyInfo> {
        public AccessTokenEntropySugReqTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(AccessTokenEntropySugReqTestImplementation);
    }
    public class AccessTokenEntropySugReqTestImplementation : EntropyTestImplementationBase {
        public AccessTokenEntropySugReqTestImplementation(TestRunContext context, AccessTokenEntropySugReqTestResult result, AccessTokenEntropyMinReqTestResult min, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, min, "access tokens", 160, t => t.AccessToken, supportedFlows) { }
    }
}
