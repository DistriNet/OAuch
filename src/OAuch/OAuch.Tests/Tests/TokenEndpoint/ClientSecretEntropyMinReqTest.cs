using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Shared;
using System;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class ClientSecretEntropyMinReqTest : Test {
        public override string Title => "Is the client secret secure (128 bits)";
        public override string Description => "This test calculates the entropy of the client secret and verifies that it conforms to the required minimum length of 128 bits";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(ClientSecretEntropyMinReqTestResult);
    }
    public class ClientSecretEntropyMinReqTestResult : TestResult<ClientSecretEntropyInfo> {
        public ClientSecretEntropyMinReqTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(ClientSecretEntropyMinReqTestImplementation);
        public override float? ImplementationScore {
            get {
                if (ExtraInfo?.Entropy == null)
                    return base.ImplementationScore;
                return Math.Min((float)(ExtraInfo.Entropy.Value / 128f), 1f);
            }
        }
    }
    public class ClientSecretEntropyMinReqTestImplementation : ClientSecretEntropyTestImplementationBase {
        public ClientSecretEntropyMinReqTestImplementation(TestRunContext context, ClientSecretEntropyMinReqTestResult result, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, null, 128, supportedFlows) { }
    }
}
