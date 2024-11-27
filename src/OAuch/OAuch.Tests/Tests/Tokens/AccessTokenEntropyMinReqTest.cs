using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Shared;
using System;

namespace OAuch.Compliance.Tests.Tokens {
    public class AccessTokenEntropyMinReqTest : Test {
        public override string Title => "Are the access tokens secure (128 bits)";
        public override string Description => "This test calculates the entropy of the access tokens and verifies that it conforms to the minimum requirements of 128 bits";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(AccessTokenEntropyMinReqTestResult);
    }
    public class AccessTokenEntropyMinReqTestResult : TestResult<EntropyInfo> {
        public AccessTokenEntropyMinReqTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(AccessTokenEntropyMinReqTestImplementation);
        public override float? ImplementationScore {
            get {
                if (ExtraInfo?.AverageEntropy == null)
                    return base.ImplementationScore;
                return Math.Min((float)(ExtraInfo.AverageEntropy.Value / 128f), 1f);
            }
        }
    }
    public class AccessTokenEntropyMinReqTestImplementation : EntropyTestImplementationBase {
        public AccessTokenEntropyMinReqTestImplementation(TestRunContext context, AccessTokenEntropyMinReqTestResult result, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, null, "access tokens", 128, t => t.AccessToken, supportedFlows) { }
    }
}
