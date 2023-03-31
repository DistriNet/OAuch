using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Tokens {
    public class DeviceCodeEntropyTest : Test {
        public override string Title => "Are the device codes secure (128 bits)";
        public override string Description => "This test calculates the entropy of the device codes and verifies that it conforms to the minimum length of 128 bits";
        public override string? TestingStrategy => null;
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(DeviceCodeEntropyTestResult);
    }
    public class DeviceCodeEntropyTestResult : TestResult<EntropyInfo> {
        public DeviceCodeEntropyTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(DeviceCodeEntropyTestImplementation);
    }
    public class DeviceCodeEntropyTestImplementation : EntropyTestImplementationBase {
        public DeviceCodeEntropyTestImplementation(TestRunContext context, DeviceCodeEntropyTestResult result, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, null, "device codes", 128, t => t.GetItem("device_code"), supportedFlows) { }
    }
}
