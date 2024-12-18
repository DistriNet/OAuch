﻿using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Shared;
using System;

namespace OAuch.Compliance.Tests.TokenEndpoint {
    public class ClientSecretEntropySugReqTest : Test {
        public override string Title => "Is the client secret secure (160 bits)";
        public override string Description => "This test calculates the entropy of the client secret and verifies that it conforms to the suggested minimum length of 160 bits";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(ClientSecretEntropySugReqTestResult);
    }
    public class ClientSecretEntropySugReqTestResult : TestResult<ClientSecretEntropyInfo> {
        public ClientSecretEntropySugReqTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(ClientSecretEntropySugReqTestImplementation);
        public override float? ImplementationScore {
            get {
                if (ExtraInfo?.Entropy == null)
                    return base.ImplementationScore;
                return Math.Min((float)(ExtraInfo.Entropy.Value / 160f), 1f);
            }
        }
    }
    public class ClientSecretEntropySugReqTestImplementation : ClientSecretEntropyTestImplementationBase {
        public ClientSecretEntropySugReqTestImplementation(TestRunContext context, ClientSecretEntropySugReqTestResult result, ClientSecretEntropyMinReqTestResult min, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, min, 160, supportedFlows) { }
    }
}
