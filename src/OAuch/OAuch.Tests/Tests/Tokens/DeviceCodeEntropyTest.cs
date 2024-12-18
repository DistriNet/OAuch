﻿using OAuch.Compliance.Tests.Features;
using OAuch.Compliance.Tests.Shared;
using OAuch.Shared;
using System;

namespace OAuch.Compliance.Tests.Tokens {
    public class DeviceCodeEntropyTest : Test {
        public override string Title => "Are the device codes secure (128 bits)";
        public override string Description => "This test calculates the entropy of the device codes and verifies that it conforms to the minimum length of 128 bits";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(DeviceCodeEntropyTestResult);
    }
    public class DeviceCodeEntropyTestResult : TestResult<EntropyInfo> {
        public DeviceCodeEntropyTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(DeviceCodeEntropyTestImplementation);
        public override float? ImplementationScore {
            get {
                if (ExtraInfo?.AverageEntropy == null)
                    return base.ImplementationScore;
                return Math.Min((float)(ExtraInfo.AverageEntropy.Value / 128f), 1f);
            }
        }
    }
    public class DeviceCodeEntropyTestImplementation : EntropyTestImplementationBase {
        public DeviceCodeEntropyTestImplementation(TestRunContext context, DeviceCodeEntropyTestResult result, HasSupportedFlowsTestResult supportedFlows)
            : base(context, result, null, "device codes", 128, t => t.GetItem("device_code"), supportedFlows) { }
    }
}
