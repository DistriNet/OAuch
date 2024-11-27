using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Shared;
using System;

namespace OAuch.Compliance.Tests.Tokens {
    public class AccessTokenEntropySugReqTest : Test {
        public override string Title => "Are the access tokens secure (160 bits)";
        public override string Description => "This test calculates the entropy of the access tokens and verifies that it conforms to the suggested requirements of 160 bits";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(AccessTokenEntropySugReqTestResult);
    }
    public class AccessTokenEntropySugReqTestResult : TestResult<EntropyInfo> {
        public AccessTokenEntropySugReqTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(AccessTokenEntropySugReqTestImplementation);
        public override float? ImplementationScore {
            get {
                if (ExtraInfo?.AverageEntropy == null)
                    return base.ImplementationScore;
                return Math.Min((float)(ExtraInfo.AverageEntropy.Value / 160f), 1f);
            }
        }
    }
    public class AccessTokenEntropySugReqTestImplementation : EntropyTestImplementationBase {
        public AccessTokenEntropySugReqTestImplementation(TestRunContext context, AccessTokenEntropySugReqTestResult result, AccessTokenEntropyMinReqTestResult min, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, min, "access tokens", 160, t => t.AccessToken, supportedFlows) { }
    }
}
