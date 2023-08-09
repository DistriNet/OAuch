using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
    }
    public class ClientSecretEntropyMinReqTestImplementation : ClientSecretEntropyTestImplementationBase {
        public ClientSecretEntropyMinReqTestImplementation(TestRunContext context, ClientSecretEntropyMinReqTestResult result, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, null, 128, supportedFlows) { }
    }
}
